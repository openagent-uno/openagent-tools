import AppKit
import Foundation
import AVFAudio
import CryptoKit

final class OwnedInputSurface: NSView {
    var dragCount = 0
    var scrollCount = 0
    var lastDrag: [Double] = []
    var lastScroll: [Double] = []
    override func mouseDown(with event: NSEvent) {}
    override func mouseDragged(with event: NSEvent) {
        dragCount += 1
        let point = convert(event.locationInWindow, from: nil)
        lastDrag = [point.x, point.y]
        needsDisplay = true
    }
    override func scrollWheel(with event: NSEvent) {
        scrollCount += 1
        lastScroll = [event.scrollingDeltaX, event.scrollingDeltaY]
        needsDisplay = true
    }
    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill(); bounds.fill()
        let label = "Owned drag \(dragCount) / scroll \(scrollCount)"
        label.draw(at: NSPoint(x: 5, y: 5), withAttributes: [.foregroundColor: NSColor.labelColor])
    }
}

// Owned acceptance fixture. It reads no user data and never touches another app.
final class Fixture: NSObject, NSApplicationDelegate {
    let title: String
    let output: URL
    let control: URL
    var window: NSWindow!
    var field: NSTextField!
    var button: NSButton!
    var rich: NSTextView!
    var inputSurface: OwnedInputSurface!
    var tone: AVAudioPlayer?
    var lastMouse: [Double] = []
    var keyEventCount = 0
    var pasteAvailable = true
    var lastKey = ""
    var lastFlags: UInt = 0
    var eventMonitor: Any?
    var clipboardDigest = ""
    var clicks = 0
    var lastCommand = ""
    var timer: Timer?
    init(title: String, output: URL, control: URL) {
        self.title = title; self.output = output; self.control = control
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let menu = NSMenu()
        let applicationItem = NSMenuItem(title: "Fixture", action: nil, keyEquivalent: "")
        applicationItem.submenu = NSMenu(title: "Fixture")
        menu.addItem(applicationItem)
        let editItem = NSMenuItem(title: "Edit", action: nil, keyEquivalent: "")
        let edit = NSMenu(title: "Edit")
        for (title, selector, key) in [("Select All", #selector(NSText.selectAll(_:)), "a"), ("Copy", #selector(NSText.copy(_:)), "c"), ("Paste", #selector(NSText.paste(_:)), "v")] {
            let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
            item.keyEquivalentModifierMask = .command
            edit.addItem(item)
        }
        editItem.submenu = edit
        menu.addItem(editItem)
        NSApp.mainMenu = menu
        eventMonitor = NSEvent.addLocalMonitorForEvents(matching: [.keyDown,.leftMouseDown,.leftMouseUp]) { [weak self] event in
            if event.type != .keyDown { self?.lastMouse = [Double(event.windowNumber),event.locationInWindow.x,event.locationInWindow.y];return event }
            self?.keyEventCount += 1
            let base = event.charactersIgnoringModifiers ?? ""
            let characters = event.characters ?? ""
            let enabled = NSApp.mainMenu?.item(withTitle: "Edit")?.submenu?.items.first?.isEnabled ?? false
            let hasTarget = NSApp.target(forAction: #selector(NSText.selectAll(_:))) != nil
            self?.lastKey = "\(base):\(characters):\(enabled):\(hasTarget)"
            self?.lastFlags = event.modifierFlags.rawValue
            return event
        }
        window = NSWindow(contentRect: NSRect(x: 100, y: 200, width: 600, height: 400), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = title
        field = NSTextField(frame: NSRect(x: 20, y: 150, width: 540, height: 30))
        field.stringValue = "initial fixture text"
        field.setAccessibilityIdentifier("oa-fixture-text")
        window.contentView!.addSubview(field)
        let secure = NSSecureTextField(frame: NSRect(x: 20, y: 100, width: 540, height: 30))
        secure.stringValue = "fixture-secret-must-not-appear"
        secure.setAccessibilityIdentifier("oa-fixture-secure")
        window.contentView!.addSubview(secure)
        button = NSButton(frame: NSRect(x: 20, y: 30, width: 200, height: 40))
        button.title = "Apply fixture"
        button.setAccessibilityIdentifier("oa-fixture-apply")
        button.target = self; button.action = #selector(pressed)
        window.contentView!.addSubview(button)
        inputSurface = OwnedInputSurface(frame: NSRect(x: 260, y: 20, width: 300, height: 60))
        inputSurface.setAccessibilityElement(true)
        inputSurface.setAccessibilityRole(.group)
        inputSurface.setAccessibilityIdentifier("oa-fixture-input-surface")
        window.contentView!.addSubview(inputSurface)
        rich = NSTextView(frame: NSRect(x: 20, y: 230, width: 540, height: 130))
        rich.isRichText = true
        rich.string = "rich fixture"
        rich.setAccessibilityIdentifier("oa-fixture-rich")
        window.contentView!.addSubview(rich)
        window.makeFirstResponder(field)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in self?.tick() }
        tick()
    }
    @objc func pressed() { clicks += 1; tick() }
    func tick() {
        if let command = try? String(contentsOf: control, encoding: .utf8), command != lastCommand {
            lastCommand = command
            if command == "quit" { NSApp.terminate(nil) }
            if command.hasPrefix("clipboard-digest") { clipboardDigest = clipboardSignature() }
            if command == "tone" { playTone() }
            if command == "select-all" { NSApp.sendAction(#selector(NSText.selectAll(_:)), to: nil, from: nil) }
            if command == "hide-paste" {
                if let edit = NSApp.mainMenu?.item(withTitle: "Edit")?.submenu {
                    for item in edit.items where item.action == #selector(NSText.paste(_:)) { edit.removeItem(item) }
                }
                pasteAvailable = false
                clipboardDigest = clipboardSignature()
            }
            if command == "block" {
                try? Data("blocked".utf8).write(to: control.appendingPathExtension("blocked"), options: .atomic)
                Thread.sleep(forTimeInterval: 2.0)
            }
            if command == "long-initial" { field.stringValue = String(repeating: "A", count: 600) + "original" }
            if command == "long-change" { field.stringValue = String(repeating: "A", count: 600) + "external" }
            if command == "external-change" { field.stringValue = "fixture external edit" }
            if command == "move" { window.setFrameOrigin(NSPoint(x: 300, y: 250)) }
        }
        let state: [String: Any] = ["pid": ProcessInfo.processInfo.processIdentifier, "title": title, "text": field.stringValue, "clicks": clicks, "rich_text": rich.string, "rich_bold": rich.textStorage.flatMap { storage -> Bool? in
            guard storage.length > 0, let font = storage.attribute(.font, at: 0, effectiveRange: nil) as? NSFont else { return false }
            return font.fontDescriptor.symbolicTraits.contains(.bold)
        } ?? false, "selection_utf16": field.currentEditor().map { [$0.selectedRange.location, $0.selectedRange.length] } ?? [], "tone_playing": tone?.isPlaying ?? false, "clipboard_digest": clipboardDigest, "last_key": lastKey, "last_flags": lastFlags, "key_event_count": keyEventCount, "paste_available": pasteAvailable, "last_mouse": lastMouse, "drag_count": inputSurface.dragCount, "scroll_count": inputSurface.scrollCount, "last_drag": inputSurface.lastDrag, "last_scroll": inputSurface.lastScroll]
        if let data = try? JSONSerialization.data(withJSONObject: state, options: [.sortedKeys]) {
            try? data.write(to: output, options: .atomic)
        }
    }
    func clipboardSignature() -> String {
        var hasher = SHA256()
        for item in NSPasteboard.general.pasteboardItems ?? [] {
            hasher.update(data: Data("item\0".utf8))
            for type in item.types.sorted(by: { $0.rawValue < $1.rawValue }) {
                hasher.update(data: Data((type.rawValue + "\0").utf8))
                if let bytes = item.data(forType: type) { hasher.update(data: bytes) }
                hasher.update(data: Data([0]))
            }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
    func playTone() {
        let samples = 48000 * 2
        var wav = Data()
        func ascii(_ text: String) { wav.append(text.data(using: .ascii)!) }
        func u16(_ value: UInt16) { var v = value.littleEndian; withUnsafeBytes(of: &v) { wav.append(contentsOf: $0) } }
        func u32(_ value: UInt32) { var v = value.littleEndian; withUnsafeBytes(of: &v) { wav.append(contentsOf: $0) } }
        ascii("RIFF");u32(UInt32(36 + samples * 2));ascii("WAVEfmt ");u32(16);u16(1);u16(1);u32(48000);u32(96000);u16(2);u16(16);ascii("data");u32(UInt32(samples * 2))
        for n in 0..<samples { let sample = Int16(sin(Double(n) * 2 * Double.pi * 440 / 48000) * 2000);u16(UInt16(bitPattern: sample)) }
        tone = try? AVAudioPlayer(data: wav);tone?.play()
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
var arguments = CommandLine.arguments
if arguments.count != 4, let url = Bundle.main.url(forResource: "FixtureConfig", withExtension: "json"),
   let data = try? Data(contentsOf: url), let config = try? JSONSerialization.jsonObject(with: data) as? [String: String],
   let title = config["title"], let state = config["state"], let control = config["control"] {
    arguments = [arguments[0], title, state, control]
}
if arguments.count != 4 { fatalError("usage: fixture title output.json control.txt") }
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let fixture = Fixture(title: arguments[1], output: URL(fileURLWithPath: arguments[2]), control: URL(fileURLWithPath: arguments[3]))
app.delegate = fixture
app.run()
