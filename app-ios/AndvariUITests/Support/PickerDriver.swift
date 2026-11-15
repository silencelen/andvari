import XCTest

/// The system's own pickers. They run outside the app and are drawn inside it, so the app's tree holds them: the file
/// picker (open a file, choose a folder, save a file) and the photo picker. A test puts its files into "On My iPhone"
/// first (FilesApp); the file picker opens there, or is taken there.
extension UITestCase {
    var filesApp: XCUIApplication { XCUIApplication(bundleIdentifier: "com.apple.DocumentsApp") }

    /// "On My iPhone" is a folder on the simulator's disk. A simulator that has not made it yet does so once the Files
    /// app has shown it: Files is then opened once, before the first file is put there.
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

    /// The file picker's own bar (its back button, the folder's name, Cancel, and Open or Save where it has one): in the
    /// app's tree for as long as the picker is up.
    private var filePickerBar: XCUIElement {
        app.navigationBars["FullDocumentManagerViewControllerNavigationBar"]
    }

    /// Whether the file picker is drawn in the app now.
    func filePickerIsUp() -> Bool {
        filePickerBar.exists
    }

    private func pickerLocations(in application: XCUIApplication) -> XCUIElementQuery {
        application.descendants(matching: .any).matching(NSPredicate(format: "identifier == 'DOC.sidebar.item.On My iPhone' OR label == 'On My iPhone'"))
    }

    private func pickerBrowse(in application: XCUIApplication) -> XCUIElementQuery {
        application.buttons.matching(NSPredicate(format: "label == 'Browse'"))
    }

    /// A file's cell in the picker's list. Files names a cell "name, kind" and leaves the extension out of the name
    /// (a kind it does not know keeps it: "name.bin, bin"), so a file is known by its name before the extension: tests
    /// give their files names that differ there. A file the picker does not take is there too, disabled.
    private func pickerFile(_ name: String) -> XCUIElement {
        let base = (name as NSString).deletingPathExtension
        return app.collectionViews["File View"].cells.matching(NSPredicate(format: "identifier BEGINSWITH %@", base)).firstMatch
    }

    /// Wait for the file picker and for the file [name] in the folder it shows. It opens on "On My iPhone" when that is
    /// where it was last; otherwise Browse, then On My iPhone, as a person goes there. False when the file never showed;
    /// the picker's tree is then kept under [tag].
    @discardableResult
    func browseFilePicker(to name: String, tag: String) -> Bool {
        let file = pickerFile(name)
        if !waitUntil(25, { self.filePickerIsUp() }) {
            dumpTree(app, as: "file-picker-\(tag)-never-came")
            return false
        }
        for _ in 0..<6 {
            if waitUntil(5, { file.exists }) { return true }
            if let location = firstHittable(pickerLocations(in: app)) {
                location.tap()
            } else if let browse = firstHittable(pickerBrowse(in: app)) {
                browse.tap()
            }
            Thread.sleep(forTimeInterval: 1.5)
        }
        dumpTree(app, as: "file-picker-\(tag)-no-file")
        return false
    }

    /// Choose files in the file picker that is coming up: as many of [names] as the picker takes in one go, which is
    /// all of them when it lets several be chosen (they are then confirmed with Open), and the first alone when a tap
    /// on a file is the choice. The names chosen; none when the first file never showed.
    func chooseInFilePicker(_ names: [String], tag: String) -> [String] {
        guard let first = names.first, browseFilePicker(to: first, tag: tag) else { return [] }
        let file = pickerFile(first)
        if !safelyHittable(file) { scrollToComfort(file, lowest: 0.85) }
        file.tap()
        var chosen = [first]
        // A picker that takes one file closes on the tap.
        if waitUntil(4, { !self.filePickerIsUp() }) { return chosen }
        for name in names.dropFirst() {
            let more = pickerFile(name)
            guard more.exists else { continue }
            if !safelyHittable(more) { scrollToComfort(more, lowest: 0.85) }
            more.tap()
            chosen.append(name)
            Thread.sleep(forTimeInterval: 0.5)
        }
        shot("file-picker-\(tag)-chosen")
        let open = filePickerBar.buttons["Open"]
        if waitUntil(5, { open.exists && open.isEnabled }) {
            open.tap()
        } else {
            dumpTree(app, as: "file-picker-\(tag)-no-open")
        }
        if !waitUntil(15, { !self.filePickerIsUp() }) {
            dumpTree(app, as: "file-picker-\(tag)-stayed")
            XCTFail("the file picker stayed up after \(chosen.joined(separator: ", ")) were chosen")
        }
        return chosen
    }

    /// Choose "On My iPhone" itself in the file picker that is coming up to choose a folder. [marker] is a file the test
    /// put there, to know the folder by: the picker shows it greyed out.
    func chooseOnMyIPhoneFolder(marker: String, tag: String) {
        if !browseFilePicker(to: marker, tag: tag) {
            XCTFail("the folder picker never showed On My iPhone (known by \(marker))")
            return
        }
        let open = filePickerBar.buttons["Open"]
        guard waitUntil(8, { open.exists && open.isEnabled }) else {
            dumpTree(app, as: "folder-picker-\(tag)-no-open")
            XCTFail("the folder picker offers no Open for On My iPhone")
            return
        }
        open.tap()
        if !waitUntil(15, { !self.filePickerIsUp() }) {
            dumpTree(app, as: "folder-picker-\(tag)-stayed")
            XCTFail("the folder picker stayed up after Open")
        }
    }

    /// The picker that saves a file ("Save to Files"), coming up: save where it stands when it offers that, in On My
    /// iPhone when it first has to be told where. Where the file landed is the caller's to find (FilesApp.files).
    func saveInFilePicker(tag: String) {
        let save = app.buttons.matching(NSPredicate(format: "label == 'Save' OR label == 'Move'"))
        let ready: () -> Bool = { self.firstHittable(save)?.isEnabled == true }
        if !waitUntil(25, { self.filePickerIsUp() || ready() }) {
            dumpTree(app, as: "save-picker-\(tag)-never-came")
            XCTFail("the picker that saves a file did not come up")
            return
        }
        Thread.sleep(forTimeInterval: 1)
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
        if waitUntil(2, { replace.exists }) { replace.tap() }
        if !waitUntil(20, { !self.filePickerIsUp() && !ready() }) {
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
