import CoreGraphics
import Foundation
// Prints 1 when the login session's screen is locked, else 0.
let d = CGSessionCopyCurrentDictionary() as? [String: Any] ?? [:]
let locked = (d["CGSSessionScreenIsLocked"] as? Bool) ?? ((d["CGSSessionScreenIsLocked"] as? Int).map { $0 != 0 } ?? false)
print(locked ? 1 : 0)
