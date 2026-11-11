import Foundation

/// The simulator's Face ID and Touch ID, driven the way Simulator's Features menu drives them: Darwin
/// notifications. The test runner is a simulator process, so it posts them itself; nothing runs on the Mac.
/// libnotify is reached through dlsym so this file needs no module that may be missing from the SDK.
enum Biometrics {
    private typealias RegisterCheck = @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<Int32>) -> UInt32
    private typealias SetState = @convention(c) (Int32, UInt64) -> UInt32
    private typealias Post = @convention(c) (UnsafePointer<CChar>) -> UInt32

    private static func symbol<T>(_ name: String, as type: T.Type) -> T? {
        // RTLD_DEFAULT
        guard let pointer = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }
        return unsafeBitCast(pointer, to: type)
    }

    @discardableResult
    private static func post(_ name: String) -> Bool {
        guard let post = symbol("notify_post", as: Post.self) else { return false }
        return name.withCString { post($0) } == 0
    }

    /// Features > Face ID > Enrolled.
    @discardableResult
    static func setEnrolled(_ enrolled: Bool) -> Bool {
        let name = "com.apple.BiometricKit.enrollmentChanged"
        guard let register = symbol("notify_register_check", as: RegisterCheck.self),
              let setState = symbol("notify_set_state", as: SetState.self)
        else { return false }
        var token: Int32 = 0
        guard name.withCString({ register($0, &token) }) == 0 else { return false }
        guard setState(token, enrolled ? 1 : 0) == 0 else { return false }
        return post(name)
    }

    /// Features > Face ID > Matching Face (and the Touch ID twin, for a simulator that has Touch ID).
    static func match() {
        post("com.apple.BiometricKit_Sim.pearl.match")
        post("com.apple.BiometricKit_Sim.fingerTouch.match")
    }

    /// Features > Face ID > Non-matching Face.
    static func noMatch() {
        post("com.apple.BiometricKit_Sim.pearl.nomatch")
        post("com.apple.BiometricKit_Sim.fingerTouch.nomatch")
    }
}
