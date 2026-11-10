# andvari for iOS

The iOS app: a SwiftUI client on the shared Kotlin core, with a system AutoFill extension and a
Safari web extension. Design: `docs/design/2026-11-09-ios-app.md`.

Building needs macOS with Xcode 26 or newer, a JDK 17, Node, and [XcodeGen](https://github.com/yonaskolb/XcodeGen):

```sh
app-ios/scripts/prepare.sh iosSimulatorArm64
(cd app-ios && xcodegen generate)
xcodebuild -project app-ios/Andvari.xcodeproj -scheme Andvari -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO build
```

`DEVELOPMENT_TEAM` and the provisioning profile names in `project.yml` are the official build's.
To build your own signed copy, change them to yours.
