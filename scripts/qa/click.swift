import CoreGraphics
import Foundation

// Tiny input-synthesis helper: click/dclick/rclick/move x y, scroll x y dy, drag x1 y1 x2 y2
let args = CommandLine.arguments
guard args.count >= 4 else { FileHandle.standardError.write("usage: click|dclick|rclick|move x y | scroll x y dy | drag x1 y1 x2 y2\n".data(using: .utf8)!); exit(2) }
let cmd = args[1]
let x = Double(args[2])!, y = Double(args[3])!
let p = CGPoint(x: x, y: y)

func post(_ e: CGEvent?) { e?.post(tap: .cghidEventTap) }

func mouseClick(count: Int64, button: CGMouseButton, down: CGEventType, up: CGEventType) {
    post(CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: p, mouseButton: .left))
    usleep(150000)
    for i in 1...count {
        let d = CGEvent(mouseEventSource: nil, mouseType: down, mouseCursorPosition: p, mouseButton: button)
        d?.setIntegerValueField(.mouseEventClickState, value: i)
        post(d)
        usleep(60000)
        let u = CGEvent(mouseEventSource: nil, mouseType: up, mouseCursorPosition: p, mouseButton: button)
        u?.setIntegerValueField(.mouseEventClickState, value: i)
        post(u)
        usleep(90000)
    }
}

switch cmd {
// Hover without clicking. Several controls only exist under the pointer — the
// header's column-select and pin icons, a view row's edit/drop buttons — so
// without this verb they cannot be driven at all, and a QA pass silently skips
// them. Two moves with a pause between: one synthetic `mouseMoved` alone often
// lands before the page has any listener attached to react to, and `:hover`
// repaints on the second.
case "move":
    post(CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: p, mouseButton: .left))
    usleep(120000)
    post(CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: p, mouseButton: .left))
case "click": mouseClick(count: 1, button: .left, down: .leftMouseDown, up: .leftMouseUp)
case "dclick": mouseClick(count: 2, button: .left, down: .leftMouseDown, up: .leftMouseUp)
case "rclick": mouseClick(count: 1, button: .right, down: .rightMouseDown, up: .rightMouseUp)
case "drag":
    guard args.count >= 6, let x2 = Double(args[4]), let y2 = Double(args[5]) else { exit(2) }
    post(CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: p, mouseButton: .left))
    usleep(150000)
    post(CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: p, mouseButton: .left))
    usleep(120000)
    // step the pointer so drag-tracking loops see motion, not a teleport
    let steps = 12
    for i in 1...steps {
        let t = Double(i) / Double(steps)
        let q = CGPoint(x: x + (x2 - x) * t, y: y + (y2 - y) * t)
        post(CGEvent(mouseEventSource: nil, mouseType: .leftMouseDragged, mouseCursorPosition: q, mouseButton: .left))
        usleep(25000)
    }
    usleep(120000)
    post(CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: CGPoint(x: x2, y: y2), mouseButton: .left))
case "scroll":
    guard args.count >= 5, let dy = Int32(args[4]) else { exit(2) }
    post(CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: p, mouseButton: .left))
    usleep(120000)
    let s = CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 1, wheel1: dy, wheel2: 0, wheel3: 0)
    post(s)
default: exit(2)
}
usleep(150000)
