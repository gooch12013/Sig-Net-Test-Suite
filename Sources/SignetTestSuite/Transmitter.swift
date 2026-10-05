import Combine
import SigNet

/// SigNet's Sender, observable for SwiftUI.
final class Transmitter: TransmitterEngine, ObservableObject {
    let objectWillChange = ObservableObjectPublisher()
    override func willChange() { objectWillChange.send() }
}
