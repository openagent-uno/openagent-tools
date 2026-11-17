"""Windows CDP bridge with an explicit host confinement/desktop adapter."""
import importlib.util
import json
import msvcrt
import os
from pathlib import Path
import subprocess
import sys
import threading


def load_host_adapter():
    path = Path(os.environ['OPENAGENT_CHROME_WINDOWS_ADAPTER'])
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError('A regular absolute Windows confinement adapter is required')
    spec = importlib.util.spec_from_file_location('openagent_browser_host_policy', path)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    return adapter


def main():
    if sys.platform != 'win32' or os.environ.get('OPENAGENT_CHROME_TRANSPORT') != 'pipe':
        raise RuntimeError('Windows native browser box required')
    pipe, binary, arguments = sys.argv[1:]
    if not pipe.startswith('\\\\.\\pipe\\LOCAL\\OpenAgent-CDP-'):
        raise RuntimeError('Private AppContainer browser pipe required')
    arguments = json.loads(arguments)
    if not isinstance(arguments, list) or not all(isinstance(item, str) for item in arguments):
        raise ValueError('Browser arguments must be a string array')
    def forbidden_switch(item):
        prefix = 2 if item.startswith('--') else 1 if item.startswith(('-', '/')) else 0
        return bool(prefix) and item[prefix:].split('=', 1)[0].lower() in ('no-sandbox', 'disable-setuid-sandbox')
    if any(forbidden_switch(item) for item in arguments):
        raise RuntimeError('Caller cannot disable the browser sandbox')
    adapter = load_host_adapter()
    confinement = adapter.verify_browser_confinement(binary)
    # Chromium cannot create its additional window station in this S4U
    # AppContainer. The verified outer host boundary confines every descendant.
    # Chromium's own renderer sandbox/CET configuration is not equivalent.
    arguments.append('--no-sandbox')
    diagnostic = os.environ.get('OPENAGENT_CHROME_QUALIFICATION_DIAGNOSTICS') == 'true'
    def report(message):
        if diagnostic: print('[OpenAgent CDP diagnostic] ' + message, file=sys.stderr, flush=True)
    report('verified kernel confinement=' + json.dumps(confinement, sort_keys=True))
    report('owned bridge qualification diagnostics active')
    if diagnostic:
        # Inspect only this bridge's own token; never change its DACL or rights.
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        for label, rights in [('QUERY', 8), ('DUPLICATE_QUERY', 10), ('ALL_ACCESS', 0xF01FF)]:
            token = wintypes.HANDLE()
            ctypes.set_last_error(0)
            allowed = bool(advapi.OpenProcessToken(kernel.GetCurrentProcess(), rights, ctypes.byref(token)))
            failure = 0 if allowed else ctypes.get_last_error()
            report('bridge own token ' + label + '=' + str(allowed) + ' error=' + str(failure))
            if allowed: kernel.CloseHandle(token)
        # Read only these two pinned browser siblings using Chromium's sharing
        # and read-only mapping contract. This observes the bridge token only.
        import hashlib
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_int64)]
        kernel.CreateFileMappingW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR]
        kernel.CreateFileMappingW.restype = wintypes.HANDLE
        kernel.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
        kernel.MapViewOfFile.restype = ctypes.c_void_p
        kernel.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
        for filename, expected_size, expected_digest in [
            ('icudtl.dat', 10819840, '495c45cc7a65562ec461f860c310c6b66e006acd96833f61d1aa31f77fe18cf1'),
            ('v8_context_snapshot.bin', 753696, 'a3b6a107d0cbe893e4255a58a2e24ea86dee3d57a57b56d65dc309b2893c2086'),
        ]:
            handle, mapping, view = None, None, None
            stage, size, success, failure = 'open', 0, False, 0
            try:
                handle = kernel.CreateFileW(os.path.join(os.path.dirname(binary), filename), 0x80000000, 7, None, 3, 0, None)
                if handle == ctypes.c_void_p(-1).value:
                    handle = None
                    raise OSError(ctypes.get_last_error(), 'owned asset open failed')
                stage = 'size'
                value = ctypes.c_int64()
                if not kernel.GetFileSizeEx(handle, ctypes.byref(value)):
                    raise OSError(ctypes.get_last_error(), 'owned asset size failed')
                size = value.value
                if size != expected_size:
                    raise OSError(13, 'owned asset size differs from pin')
                stage = 'mapping'
                mapping = kernel.CreateFileMappingW(handle, None, 2, 0, 0, None)
                if not mapping: raise OSError(ctypes.get_last_error(), 'owned asset mapping failed')
                stage = 'view'
                view = kernel.MapViewOfFile(mapping, 4, 0, 0, 0)
                if not view: raise OSError(ctypes.get_last_error(), 'owned asset view failed')
                stage = 'hash'
                digest = hashlib.sha256()
                for offset in range(0, size, 1024 * 1024):
                    digest.update(ctypes.string_at(view + offset, min(1024 * 1024, size - offset)))
                success = digest.hexdigest() == expected_digest
                if not success: failure = 13
            except OSError as error:
                failure = error.winerror if getattr(error, 'winerror', None) is not None else error.errno
            finally:
                if view: kernel.UnmapViewOfFile(view)
                if mapping: kernel.CloseHandle(mapping)
                if handle: kernel.CloseHandle(handle)
            report('bridge asset=' + filename + ' size=' + str(size) + ' stage=' + stage + ' success=' + str(success) + ' error=' + str(failure))
    # Qualification only: collect this child's debugger output before an early
    # CHECK abort can initialize Chromium logging. No production process uses
    # debugger flags, and no unrelated process is attached or inspected.
    debug = diagnostic and os.environ.get('OPENAGENT_CHROME_QUALIFICATION_DEBUGGER') == 'true'
    def debug_child(child):
        import ctypes
        from ctypes import wintypes
        class Event(ctypes.Structure):
            _fields_ = [('code', wintypes.DWORD), ('pid', wintypes.DWORD), ('tid', wintypes.DWORD), ('data', ctypes.c_uint64 * 20)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.WaitForDebugEvent.argtypes = [ctypes.POINTER(Event), wintypes.DWORD]
        kernel.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
        kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        kernel.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_int64, ctypes.POINTER(ctypes.c_int64), wintypes.DWORD]
        kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenThread.restype = wintypes.HANDLE
        kernel.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        modules = []
        module_failures = 0
        def image_size(header):
            if len(header) < 64 or header[:2] != b'MZ': return 0
            pe = int.from_bytes(header[60:64], 'little')
            optional = pe + 24
            if pe < 64 or optional + 60 > len(header) or header[pe:pe + 4] != b'PE\0\0' or header[pe + 4:pe + 6] != b'\x64\x86' or header[optional:optional + 2] != b'\x0b\x02': return 0
            size = int.from_bytes(header[optional + 56:optional + 60], 'little')
            return size if 0 < size <= 1024 * 1024 * 1024 else 0
        def record_module(raw, base_offset, *, main_image=False):
            # The debugger provides a handle for a file already loaded by this
            # child. Read at most its first 4 KiB; emit no paths or addresses.
            nonlocal module_failures
            handle = int.from_bytes(raw[:8], 'little')
            base = int.from_bytes(raw[base_offset:base_offset + 8], 'little')
            stage, name, size, failure = 'handle', '', 0, 0
            try:
                if not handle or handle == ctypes.c_void_p(-1).value:
                    handle = None
                    raise OSError(6, 'owned debug module has no file handle')
                stage = 'name'
                path = ctypes.create_unicode_buffer(32768)
                used = kernel.GetFinalPathNameByHandleW(handle, path, len(path), 12)  # FILE_NAME_OPENED | VOLUME_NAME_NONE
                if not 0 < used < len(path): raise OSError(ctypes.get_last_error(), 'owned module name unavailable')
                name = os.path.basename(path.value)
                if not name or len(name) > 96 or any(char not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-' for char in name): raise OSError(13, 'owned module basename rejected')
                stage = 'position'
                position = ctypes.c_int64()
                if not kernel.SetFilePointerEx(handle, 0, ctypes.byref(position), 1): raise OSError(ctypes.get_last_error(), 'owned module position unavailable')
                if not kernel.SetFilePointerEx(handle, 0, None, 0): raise OSError(ctypes.get_last_error(), 'owned module seek failed')
                stage = 'read'
                data, count = ctypes.create_string_buffer(4096), wintypes.DWORD()
                try:
                    if not kernel.ReadFile(handle, data, len(data), ctypes.byref(count), None): raise OSError(ctypes.get_last_error(), 'owned module header unreadable')
                finally:
                    kernel.SetFilePointerEx(handle, position.value, None, 0)
                stage = 'header'
                size = image_size(data.raw[:count.value])
                if not size: raise OSError(13, 'owned module PE header rejected')
            except OSError as error:
                failure = error.winerror if getattr(error, 'winerror', None) is not None else error.errno
                if main_image or module_failures < 8:
                    report('owned module hFile main=' + str(main_image) + ' stage=' + stage + ' error=' + str(failure))
                    module_failures += 1
            finally:
                if handle: kernel.CloseHandle(handle)
            if not size and main_image:
                # The image event's base belongs to the executable explicitly
                # passed to CreateProcessW. If its debugger hFile is unusable,
                # read only that same executable's bounded public PE header.
                try:
                    with open(binary, 'rb') as source: size = image_size(source.read(4096))
                    name = os.path.basename(binary)
                except OSError:
                    size = 0
                report('owned main image header fallback success=' + str(bool(size)) + ' size=' + str(size))
            if base and size and len(modules) < 256:
                modules.append((base, size, name))
        def desktop_result(thread_id):
            # At this pinned trap, EAX still holds CreateAlternateDesktop's
            # ResultCode: call -> test EAX -> nonzero branch -> int3. Observe
            # only that bounded integer from the stopped owned event thread.
            handle = kernel.OpenThread(8, False, thread_id)  # THREAD_GET_CONTEXT
            if not handle:
                report('owned desktop result context=False error=' + str(ctypes.get_last_error()))
                return
            try:
                storage = ctypes.create_string_buffer(1232 + 15)
                context = (ctypes.addressof(storage) + 15) & ~15
                ctypes.c_uint32.from_address(context + 48).value = 0x100002  # CONTEXT_AMD64 | CONTEXT_INTEGER
                if not kernel.GetThreadContext(handle, context):
                    report('owned desktop result context=False error=' + str(ctypes.get_last_error()))
                    return
                result = ctypes.c_uint64.from_address(context + 120).value & 0xFFFFFFFF  # EAX
                if 0 < result <= 72:
                    report('owned desktop result context=True code=' + str(result))
                else:
                    report('owned desktop result context=True codeInRange=False')
            finally:
                kernel.CloseHandle(handle)
        initial_breakpoint = True
        desktop_result_inspected = False
        while True:
            event = Event()
            if not kernel.WaitForDebugEvent(ctypes.byref(event), 1000):
                if child.poll() is not None: return
                continue
            status = 0x00010002
            if event.pid != child.pid:
                kernel.ContinueDebugEvent(event.pid, event.tid, status)
                continue
            if event.code in (3, 6):
                record_module(bytes(event.data), 24 if event.code == 3 else 8, main_image=event.code == 3)
            elif event.code == 7:
                base = int.from_bytes(bytes(event.data)[:8], 'little')
                modules[:] = [entry for entry in modules if entry[0] != base]
            elif event.code == 8:
                address = event.data[0]
                raw = bytes(event.data)
                unicode = int.from_bytes(raw[8:10], 'little')
                length = int.from_bytes(raw[10:12], 'little')
                if address and 0 < length < 24000:
                    data = ctypes.create_string_buffer(length * (2 if unicode else 1))
                    used = ctypes.c_size_t()
                    if kernel.ReadProcessMemory(int(child._handle), address, data, len(data), ctypes.byref(used)):
                        report(data.raw[:used.value].decode('utf-16-le' if unicode else 'utf-8', errors='replace').rstrip('\x00'))
            elif event.code == 1:
                raw = bytes(event.data)
                code = int.from_bytes(raw[:4], 'little')
                address = int.from_bytes(raw[16:24], 'little')
                chance = int.from_bytes(raw[152:156], 'little')
                location = next((name + '+RVA:' + hex(address - base) for base, size, name in modules if base <= address < base + size), 'UNKNOWN')
                report('exception=' + hex(code) + ' firstChance=' + str(chance) + ' initialBreakpoint=' + str(code == 0x80000003 and initial_breakpoint) + ' module=' + location)
                if code == 0x80000003 and location == 'chrome-headless-shell.exe+RVA:0x251f414' and not desktop_result_inspected:
                    desktop_result_inspected = True
                    desktop_result(event.tid)
                if code == 0x80000003 and initial_breakpoint: initial_breakpoint = False
                else:
                    status = 0x80010001
            if event.code == 5:
                code = int.from_bytes(bytes(event.data)[:4], 'little')
                report('browser debug exit=' + str(code) + ' (' + hex(code) + ')')
            kernel.ContinueDebugEvent(event.pid, event.tid, status)
            if event.code == 5: return
    # Creating a Win32 window before Chrome can initialize the process window
    # station and change the failure being investigated. This distinct opt-in
    # probe is deliberately absent from the real S4U agent diagnostics.
    if diagnostic and os.environ.get('OPENAGENT_CHROME_QUALIFICATION_WINDOW_PROBE') == 'true':
        import ctypes
        from ctypes import wintypes
        user = ctypes.WinDLL('user32', use_last_error=True)
        user.CreateWindowExW.restype = wintypes.HWND
        user.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, ctypes.c_void_p]
        user.DestroyWindow.argtypes = [wintypes.HWND]
        window = user.CreateWindowExW(0, 'STATIC', 'Browser qualification', 0, 0, 0, 1, 1, ctypes.c_void_p(-3), None, None, None)
        failure = ctypes.get_last_error()
        report('private message-only window=' + str(bool(window)) + ' error=' + str(failure))
        if not window: raise RuntimeError('Confined message-only window denied: ' + str(failure))
        user.DestroyWindow(window)
    # Anonymous pipes have no discoverable endpoint. Chrome inherits exactly
    # two CDP handles and three standard handles, with no other authority.
    child_read, parent_write = os.pipe()
    parent_read, child_write = os.pipe()
    read_handle, write_handle = msvcrt.get_osfhandle(child_read), msvcrt.get_osfhandle(child_write)
    child = None
    with open(pipe + '-input', 'rb', buffering=0) as input_channel, open(pipe + '-output', 'r+b', buffering=0) as output_channel:
        try:
            os.set_handle_inheritable(read_handle, True)
            os.set_handle_inheritable(write_handle, True)
            child = adapter.spawn_private_browser(binary, [*arguments,
                f'--remote-debugging-io-pipes={read_handle},{write_handle}'],
                [read_handle, write_handle], debug=debug)
            report('browser launched pid=' + str(child.pid))
            if diagnostic:
                # Inspect USER32 only after the production CreateProcessW call.
                # Log classifications rather than owner SID or logon paths.
                import ctypes
                from ctypes import wintypes
                user = ctypes.WinDLL('user32', use_last_error=True)
                kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                user.GetProcessWindowStation.restype = wintypes.HANDLE
                user.GetThreadDesktop.argtypes = [wintypes.DWORD]
                user.GetThreadDesktop.restype = wintypes.HANDLE
                user.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
                def object_name(handle):
                    value = ctypes.create_unicode_buffer(256)
                    needed = wintypes.DWORD()
                    if not handle or not user.GetUserObjectInformationW(handle, 2, value, ctypes.sizeof(value), ctypes.byref(needed)):
                        return 'unavailable:' + str(ctypes.get_last_error())
                    return value.value
                station = object_name(user.GetProcessWindowStation())
                desktop = object_name(user.GetThreadDesktop(kernel.GetCurrentThreadId()))
                report('bridge station=' + ('private-host-desktop' if station.startswith('private-host-desktop.') else 'WinSta0' if station.lower() == 'winsta0' else 'noninteractive-other' if not station.startswith('unavailable:') else station) + ' desktop=' + ('agent' if desktop == 'agent' else 'other' if not desktop.startswith('unavailable:') else desktop))
                threading.Thread(target=lambda: report('browser exit=' + str(child.wait())), daemon=True).start()
            os.close(child_read); child_read = None
            os.close(child_write); child_write = None

            def forward(source, destination, *, from_channel=False):
                try:
                    while True:
                        data = source.read(65536)
                        if not data: break
                        report(('input' if from_channel else 'output') + ' bytes=' + str(len(data)))
                        remaining = memoryview(data)
                        while remaining:
                            written = destination.write(remaining)
                            if not written: raise OSError('Native browser pipe stopped accepting data')
                            remaining = remaining[written:]
                except (OSError, ValueError) as error:
                    report(('input' if from_channel else 'output') + ' failure=' + str(error))
                finally:
                    if from_channel and child.poll() is None:
                        child.terminate()

            with os.fdopen(parent_read, 'rb', buffering=0) as incoming, os.fdopen(parent_write, 'wb', buffering=0) as outgoing:
                reader = threading.Thread(target=forward, args=(input_channel, outgoing), kwargs={'from_channel': True}, daemon=True)
                reader.start()
                if debug:
                    threading.Thread(target=forward, args=(incoming, output_channel), daemon=True).start()
                    debug_child(child)
                else:
                    forward(incoming, output_channel)
                    # Observe the owned process's natural exit before cleanup
                    # can replace its status with our termination code.
                    try: child.wait(timeout=3)
                    except subprocess.TimeoutExpired: pass
        finally:
            for descriptor in [child_read, child_write]:
                if descriptor is not None: os.close(descriptor)
            if child is not None and child.poll() is None:
                child.terminate()
                try: child.wait(timeout=3)
                except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
            if child is not None and child.returncode is not None and (child.returncode != 0 or diagnostic):
                print('[OpenAgent CDP diagnostic] owned browser final exit=' + str(child.returncode) + ' (' + hex(child.returncode) + ')', file=sys.stderr, flush=True)


if __name__ == '__main__':
    main()
