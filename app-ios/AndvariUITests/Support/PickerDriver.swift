import XCTest

/// The system's own pickers. They run outside the app and are drawn inside it, so the app's tree holds them: the file
/// picker (open a file, choose a folder, save a file) and the photo picker. A test puts its files into "On My iPhone"
/// first (FilesApp) and the file picker is taken there.
extension UITestCase {
    var filesApp: XCUIApplication { XCUIApplication(bundleIdentifier: "com.apple.DocumentsApp") }

    /// "On My iPhone" is a folder on the simulator's disk once the Files app has shown it: Files is opened once, before
    /// the first file is put there.
    func requireFilesStorage() {
        if FilesApp.localStorage() != nil { return }
        let files = filesApp
        files.launch()
        if !waitUntil(20, { FilesApp.localStorage() != nil }) {
            // Browse > On My iPhone has the Files app read the folder, which makes it.
            for _ in 0..<3 where FilesApp.localStorage() == nil {
                if let location = firstHittable(pickerLocations(in: files)) {
                    location.tap()
                } else if let browse = firstHittable(pickerBrowse(in: files)) {
                    browse.tap()
                }
                _ = waitUntil(6) { FilesApp.localStorage() != nil }
            }
        }
        dumpTree(files, as: "files-app")
        shot("files-app")
        files.terminate()
        XCTAssertNotNil(FilesApp.localStorage(), "the simulator has no On My iPhone folder (the group com.apple.FileProvider.LocalStorage) even after the Files app was opened; its groups are \(SimulatorDisk.groups())")
    }

    /// The first element of [query] that can be tapped now. A picker is drawn over the screen that raised it, and that
    /// screen's own elements stay in the tree under it: by name alone a query can find one of those.
    func firstHittable(_ query: XCUIElementQuery, limit: Int = 12) -> XCUIElement? {
        for index in 0..<min(query.count, limit) {
            let candidate = query.element(boundBy: index)
            if safelyHittable(candidate) { return candidate }
        }
        return nil
    }

    // MARK: - The file picker

    private func pickerLocations(in application: XCUIApplication) -> XCUIElementQuery {
        application.descendants(matching: .any).matching(NSPredicate(format: "identifier == 'DOC.sidebar.item.On My iPhone' OR label == 'On My iPhone'"))
    }

    private func pickerBrowse(in application: XCUIApplication) -> XCUIElementQuery {
        application.buttons.matching(NSPredicate(format: "label == 'Browse' OR identifier == 'Browse'"))
    }

    /// A file in the picker. Files shows a name without its extension and reads a file as "name, kind", so a file is
    /// known by the name before its extension: tests give their files names that differ there.
    private func pickerFile(_ name: String) -> XCUIElementQuery {
        let base = (name as NSString).deletingPathExtension
        return app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@ OR identifier BEGINSWITH %@", base, base))
    }

    /// Whether the file picker is drawn in the app now.
    func filePickerIsUp() -> Bool {
        app.descendants(matching: .any).matching(NSPredicate(format: "identifier CONTAINS 'DocumentManager' OR identifier BEGINSWITH 'DOC.' OR label == 'Browse' OR label == 'Recents'")).firstMatch.exists
    }

    /// Take the file picker that is coming up to "On My iPhone", until it shows the file [name] there. The picker opens
    /// where it was last, or on Recents: Browse, then On My iPhone, as a person goes. False when the file never showed;
    /// the picker's tree is kept either way, under [tag].
    @discardableResult
    func browseFilePicker(to name: String, tag: String) -> Bool {
        let file = pickerFile(name)
        let shown: () -> Bool = { self.firstHittable(file) != nil || (file.firstMatch.exists && self.filePickerIsUp() && self.onScreen(file.firstMatch)) }
        _ = waitUntil(15) { self.filePickerIsUp() }
        Thread.sleep(forTimeInterval: 1.5)
        for attempt in 0..<8 {
            if waitUntil(3, shown) {
                dumpTree(app, as: "file-picker-\(tag)-showing")
                return true
            }
            if attempt < 3 {
                dumpTree(app, as: "file-picker-\(tag)-\(attempt)")
                shot("file-picker-\(tag)-\(attempt)")
            }
            if let location = firstHittable(pickerLocations(in: app)) {
                location.tap()
            } else if let browse = firstHittable(pickerBrowse(in: app)) {
                browse.tap()
            }
            Thread.sleep(forTimeInterval: 2)
        }
        dumpTree(app, as: "file-picker-\(tag)-no-file")
        dumpTree(springboard, as: "file-picker-\(tag)-no-file-springboard")
        return false
    }

    /// Choose files in the file picker that is coming up: as many of [names] as the picker takes in one go, which is
    /// all of them when it lets several be chosen (they are then confirmed with Open), and the first alone when a tap
    /// on a file is the choice. The names chosen; none when the first file never showed.
    func chooseInFilePicker(_ names: [String], tag: String) -> [String] {
        guard let first = names.first, browseFilePicker(to: first, tag: tag), let file = firstHittable(pickerFile(first)) else { return [] }
        file.tap()
        var chosen = [first]
        // A picker that takes one file closes on the tap.
        if waitUntil(4, { !self.filePickerIsUp() }) { return chosen }
        for name in names.dropFirst() {
            guard let more = firstHittable(pickerFile(name)) else { continue }
            more.tap()
            chosen.append(name)
            Thread.sleep(forTimeInterval: 0.5)
        }
        shot("file-picker-\(tag)-chosen")
        let open = app.buttons.matching(NSPredicate(format: "label == 'Open'"))
        if let button = firstHittable(open), button.isEnabled {
            button.tap()
        } else {
            dumpTree(app, as: "file-picker-\(tag)-no-open")
        }
        if !waitUntil(10, { !self.filePickerIsUp() }) {
            dumpTree(app, as: "file-picker-\(tag)-stayed")
            XCTFail("the file picker stayed up after \(chosen.joined(separator: ", ")) were chosen")
        }
        return chosen
    }

    /// Choose "On My iPhone" itself in the file picker that is coming up to choose a folder. [marker] is a file the test
    /// put there, to know the folder by.
    func chooseOnMyIPhoneFolder(marker: String, tag: String) {
        if !browseFilePicker(to: marker, tag: tag) {
            XCTFail("the folder picker never showed On My iPhone (known by \(marker))")
            return
        }
        let open = app.buttons.matching(NSPredicate(format: "label == 'Open'"))
        guard waitUntil(8, { self.firstHittable(open)?.isEnabled == true }), let button = firstHittable(open) else {
            dumpTree(app, as: "folder-picker-\(tag)-no-open")
            XCTFail("the folder picker offers no Open for On My iPhone")
            return
        }
        button.tap()
        if !waitUntil(10, { !self.filePickerIsUp() }) {
            dumpTree(app, as: "folder-picker-\(tag)-stayed")
            XCTFail("the folder picker stayed up after Open")
        }
    }

    /// The picker that saves a file ("Save to Files"), coming up: save where it stands when it offers that, in On My
    /// iPhone when it first has to be told where. Where the file landed is the caller's to find (FilesApp.files).
    func saveInFilePicker(tag: String) {
        let save = app.buttons.matching(NSPredicate(format: "label == 'Save' OR label == 'Move'"))
        let ready: () -> Bool = { self.firstHittable(save)?.isEnabled == true }
        _ = waitUntil(15) { self.filePickerIsUp() }
        Thread.sleep(forTimeInterval: 1.5)
        dumpTree(app, as: "save-picker-\(tag)")
        shot("save-picker-\(tag)")
        for _ in 0..<4 where !ready() {
            if let location = firstHittable(pickerLocations(in: app)) {
                location.tap()
            } else if let browse = firstHittable(pickerBrowse(in: app)) {
                browse.tap()
            }
            _ = waitUntil(4, ready)
        }
        guard ready(), let button = firstHittable(save) else {
            dumpTree(app, as: "save-picker-\(tag)-no-save")
            dumpTree(springboard, as: "save-picker-\(tag)-no-save-springboard")
            XCTFail("the picker that saves a file offers no Save")
            return
        }
        button.tap()
        // A file of that name already there: keep both is not offered everywhere, replace is.
        let replace = app.buttons.matching(NSPredicate(format: "label == 'Replace'")).firstMatch
        if waitUntil(3, { replace.exists }) { replace.tap() }
        if !waitUntil(15, { !self.filePickerIsUp() }) {
            dumpTree(app, as: "save-picker-\(tag)-stayed")
            XCTFail("the picker that saves a file stayed up after Save")
        }
    }

    // MARK: - The photo picker

    /// Choose the first picture in the photo picker that is coming up, and confirm it (the app lets several be chosen,
    /// so the picker waits for Add). False when the picker showed no picture.
    @discardableResult
    func chooseFirstPhoto(tag: String) -> Bool {
        let pictures = app.images.matching(NSPredicate(format: "label BEGINSWITH[c] 'Photo' OR label BEGINSWITH[c] 'Live Photo' OR label BEGINSWITH[c] 'Screenshot' OR label BEGINSWITH[c] 'Image'"))
        if !waitUntil(30, { self.firstHittable(pictures) != nil }) {
            dumpTree(app, as: "photo-picker-\(tag)-no-picture")
            dumpTree(springboard, as: "photo-picker-\(tag)-no-picture-springboard")
            return false
        }
        dumpTree(app, as: "photo-picker-\(tag)")
        firstHittable(pictures)?.tap()
        Thread.sleep(forTimeInterval: 1)
        shot("photo-picker-\(tag)-chosen")
        let confirm = app.buttons.matching(NSPredicate(format: "label == 'Add' OR label == 'Done'"))
        if waitUntil(8, { self.firstHittable(confirm)?.isEnabled == true }), let button = firstHittable(confirm) {
            button.tap()
        } else {
            dumpTree(app, as: "photo-picker-\(tag)-no-add")
        }
        return true
    }
}
