import Combine
import Foundation
import SigNet

/// SigNet's settings and Manager engines, observable for SwiftUI.
final class SecuritySettings: SecurityConfig, ObservableObject {
    let objectWillChange = ObservableObjectPublisher()
    override func willChange() { objectWillChange.send() }
}

final class Manager: ManagerEngine, ObservableObject {
    let objectWillChange = ObservableObjectPublisher()
    override func willChange() { objectWillChange.send() }
    var securitySettings: SecuritySettings { settings as! SecuritySettings } // the app only makes Managers with these
}
