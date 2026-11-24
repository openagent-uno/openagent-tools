"""Separate guest clients attach to one PTY; preview has no ambient network authority."""
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import time
import unittest
from uuid import uuid4

from openagent_shell.task_surfaces import origin, preview


class PreviewTests(unittest.TestCase):
    def test_fixed_guest_origin_and_safe_markup(self):
        class Page(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/other")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b'<h2 onclick="go()">Workspace</h2><script>secret()</script><img src="//other/"><iframe srcdoc="x"></iframe><p>&lt;b&gt;</p>')

            def log_message(self, *args):
                pass

        with HTTPServer(("127.0.0.1", 0), Page) as server:
            worker = Thread(target=server.serve_forever)
            worker.start()
            try:
                port = server.server_port
                value = preview(origin(f"{port}:/"))
                self.assertEqual(value["mime"], "text/html")
                html = base64.b64decode(value["data"]).decode()
                self.assertIn("<h2>Workspace</h2>", html)
                self.assertIn("<p>&lt;b&gt;</p>", html)
                for forbidden in ("secret()", "onclick", "src=", "iframe", "<script", "srcdoc"):
                    self.assertNotIn(forbidden, html)
                with self.assertRaises(ValueError):
                    preview((port, "/redirect"))
                for endpoint in ("22:/", "8080://outside", "https://elsewhere/", "8080:/../other"):
                    with self.assertRaises(ValueError):
                        origin(endpoint)
            finally:
                server.shutdown()
                worker.join()


@unittest.skipUnless(sys.platform == "linux", "The enrolled guest uses Linux PTYs")
class TerminalTests(unittest.TestCase):
    def test_reconnect_input_dedup_final_exit_and_cursor(self):
        from openagent_shell.task_terminal import terminal
        with TemporaryDirectory() as temp:
            root = Path(temp)
            store = root / "terminal"
            with self.assertRaises(ValueError):
                terminal(store, root, {"op": "attach"})
            first = terminal(store, root, {"op": "open"})
            ident = first["terminal_id"]
            self.assertEqual(first["status"], "running")
            request_id = str(uuid4())
            command = "printf 'one\\n' >> observation; pwd; printf '%s%s\\n' marker- delivered\n"
            write = {"op": "input", "terminal_id": ident, "request_id": request_id, "text": command}
            terminal(store, root, write)
            terminal(store, root, write)
            with self.assertRaises(ValueError):
                terminal(store, root, {**write, "text": "false\n"})
            def wait(check, timeout=8):
                start = time.monotonic()
                while time.monotonic()-start < timeout:
                    value = terminal(store, root, {"op":"read", "terminal_id":ident, "cursor":0})
                    if check(value):
                        return value
                    time.sleep(.05)
                self.fail("Missing guest output")
            result = wait(lambda r: "marker-delivered" in r["output"])
            self.assertIn(str(root), result["output"])
            self.assertEqual((root / "observation").read_bytes(), b"one\n")
            self.assertEqual(terminal(store, root, {"op":"attach"})["terminal_id"], ident)
            with self.assertRaises(ValueError):
                terminal(store, root, {"op":"read", "terminal_id":str(uuid4()), "cursor":0})
            terminal(store, root, {"op":"input", "terminal_id":ident, "request_id":str(uuid4()), "text":"exit 7\n"})
            final = wait(lambda r: r["status"] == "exited")
            self.assertEqual(final["exit_code"], 7)
            self.assertEqual(terminal(store, root, {"op":"read","terminal_id":ident,"cursor":final["end"]})["output"], "")
            self.assertEqual(terminal(store, root, {"op":"open"})["status"], "exited")
