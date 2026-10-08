import CoreGraphics
import Foundation
// Print "id x y w h" for every on-screen window whose owner name matches argv[1].
let want = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "SQLite Explorer"
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as! [[String: Any]]
for w in list {
    let owner = w[kCGWindowOwnerName as String] as? String ?? ""
    guard owner.contains(want) else { continue }
    let id = w[kCGWindowNumber as String] as? Int ?? 0
    let b = w[kCGWindowBounds as String] as? [String: Double] ?? [:]
    // Every on-screen window the app owns, with its layer, so a caller can count
    // them (main window + any alert) and pick the one it wants: layer 0 is an
    // ordinary window; an app-modal NSAlert did NOT show up under the expected
    // NSModalPanelWindowLevel (8) on macOS 26, so no layer is filtered here —
    // consumers grep "layer=0" for the document window.
    let layer = w[kCGWindowLayer as String] as? Int ?? -1
    print("\(id) \(Int(b["X"] ?? 0)) \(Int(b["Y"] ?? 0)) \(Int(b["Width"] ?? 0)) \(Int(b["Height"] ?? 0)) \(owner) layer=\(layer)")
}
