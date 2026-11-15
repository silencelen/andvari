import CryptoKit
import UIKit
import XCTest

/// Files on items: added from the Files app and from the photo picker, opened (text, a PDF, an image, a kind andvari
/// does not show), saved back to Files byte for byte, and a save that is still sending its files when the app leaves
/// the screen. The files come from the runner, which writes them into the simulator's On My iPhone (FilesApp); the
/// picture in Photos is put there when the simulator is made (boot-simulator.sh). The document scanner needs a camera.
final class T7AttachmentTests: UITestCase {
    private let stamp = Int(Date().timeIntervalSince1970) % 100000

    /// A note with a text file, a PDF and an image chosen in Files: each is listed in the item, opens as what it is,
    /// and Save to Files writes back the bytes that were added.
    func test01_FilesFromFilesOpenAndSaveBack() {
        let note = "Files \(stamp)"
        let words = "andvari UI test text file \(stamp)"
        let pdfWords = "andvari UI test PDF \(stamp)"
        let text = (name: "uitest-text-\(stamp).txt", data: Data((words + "\nsecond line\n").utf8))
        let pdf = (name: "uitest-pdf-\(stamp).pdf", data: Self.pdf(saying: pdfWords))
        let image = (name: "uitest-image-\(stamp).png", data: Self.png())
        let files = [text, pdf, image]
        step("files-in-on-my-iphone") {
            requireFilesStorage()
            for file in files {
                XCTAssertTrue(FilesApp.put(file.name, file.data), "\(file.name) could not be written into On My iPhone")
            }
        }
        step("new-note") {
            freshVault()
            openNewNote(note)
        }
        step("files-chosen") {
            addFromFiles(files.map { $0.name }, tag: "three")
        }
        step("saved") {
            saveNote(note)
        }
        step("listed-in-the-item") {
            openAnyItem(note)
            for file in files {
                XCTAssertTrue(scrollToComfort(detailFile(file.name)), "\(file.name) is not among the item's files")
            }
        }
        // The originals leave Files: what Save to Files writes there next is the item's own copy.
        for file in files { FilesApp.remove(file.name) }
        step("text-shown-and-saved-back") {
            openFile(text.name)
            let shown = app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", words)).firstMatch
            XCTAssertTrue(waitUntil(10) { shown.exists }, "the text file's words are not shown: \(previewWords())")
            XCTAssertEqual(saveOpenFileToFiles(text.name), text.data, "the text file saved to Files is not the file that was added")
            closeFile(text.name)
        }
        step("pdf-shown-and-saved-back") {
            openFile(pdf.name)
            XCTAssertNil(previewRefusal(), "the PDF is not shown")
            // PDFKit reads a page's text out to accessibility on some versions: noted when it does, not required.
            let page = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", pdfWords, pdfWords)).firstMatch
            let read = waitUntil(5) { page.exists }
            note(read ? "the PDF's words are readable in the opened file" : "the PDF is shown; its words are not in the accessibility tree")
            XCTAssertEqual(saveOpenFileToFiles(pdf.name), pdf.data, "the PDF saved to Files is not the file that was added")
            closeFile(pdf.name)
        }
        step("image-shown-and-saved-back") {
            openFile(image.name)
            let picture = app.descendants(matching: .any).matching(NSPredicate(format: "label == 'Image'")).firstMatch
            XCTAssertTrue(waitUntil(15) { picture.exists }, "the image is not shown: \(previewWords())")
            XCTAssertEqual(saveOpenFileToFiles(image.name), image.data, "the image saved to Files is not the file that was added")
            closeFile(image.name)
        }
    }

    /// A note with a picture chosen in the photo picker: it is listed under the name Photos gives it and opens as an
    /// image.
    func test02_PictureFromThePhotoPicker() {
        let note = "Photo \(stamp)"
        var name = ""
        step("new-note") {
            freshVault()
            openNewNote(note)
        }
        step("picture-chosen") {
            openAddMenu("Photo or video")
            XCTAssertTrue(chooseFirstPhoto(tag: "note"), "the photo picker showed no picture (boot-simulator.sh puts one into Photos)")
            let added = app.buttons.matching(NSPredicate(format: "label BEGINSWITH 'Remove '"))
            if !waitUntil(60, { added.count == 1 }) {
                dumpTree(app, as: "picture-not-added")
                XCTFail("the picture is not among the editor's files. The editor says: \(editorWords())")
                return
            }
            name = String(added.firstMatch.label.dropFirst("Remove ".count))
            note("the picture from Photos was added as \(name)")
        }
        step("saved") {
            saveNote(note)
        }
        step("shown-as-an-image") {
            openAnyItem(note)
            openFile(name)
            let picture = app.descendants(matching: .any).matching(NSPredicate(format: "label == 'Image'")).firstMatch
            XCTAssertTrue(waitUntil(15) { picture.exists }, "the picture is not shown: \(previewWords())")
            closeFile(name)
        }
    }

    /// The add menu's Scan a document is there only where the system has a document camera, and the simulator has none.
    func test03_DocumentScanner() throws {
        var offered = false
        step("add-menu") {
            freshVault()
            openNewItemEditor("New note")
            require(app.navigationBars["New note"], "the note editor")
            openAddFileMenu()
            XCTAssertTrue(app.buttons["Photo or video"].exists, "the Add a file menu has no Photo or video")
            offered = app.buttons["Scan a document"].exists
        }
        try skip("The document scanner is not available in the iOS simulator: it has no camera, and VNDocumentCameraViewController.isSupported is false there. The Add a file menu \(offered ? "still offers Scan a document, which cannot make a scan here" : "accordingly offers no Scan a document (checked above), only Choose a file and Photo or video"). A scan needs a real iPhone.")
    }

    /// A note saved with three large files while the server stalls: the app leaves the screen with the files still
    /// going up, and comes back. The note is then in the vault once, with its three files, and one saved back to Files
    /// is the file that was added.
    func test04_SaveStillSendingFilesWhenTheAppLeaves() {
        let note = "Upload \(stamp)"
        let files = (1...3).map { index in (name: "uitest-big-\(index)-\(stamp).bin", data: Self.random(20 * 1024 * 1024)) }
        step("large-files-in-on-my-iphone") {
            requireFilesStorage()
            for file in files {
                XCTAssertTrue(FilesApp.put(file.name, file.data), "\(file.name) could not be written into On My iPhone")
            }
        }
        step("new-note-with-the-files") {
            freshVault()
            openNewNote(note)
            addFromFiles(files.map { $0.name }, tag: "large", timeout: 240)
        }
        var setAside = 0
        step("saved-and-left-while-sending") {
            // The server stops for a few seconds, as a network stalls: the files cannot all be up when the app leaves.
            XCTAssertNil(OtherDevice.stallServer(seconds: 6), "the server could not be stalled")
            app.navigationBars["New note"].buttons["Save"].tap()
            XCUIDevice.shared.press(.home)
            setAside = LocalState.filesSetAside().count
            XCTAssertGreaterThan(setAside, 0, "no file of the save was still set aside on the device when the app left: the save had already finished")
            note("the app left the screen with \(setAside) files of the save still set aside on the device")
        }
        step("away") {
            // Longer than the stall, shorter than the half minute a lock waits for an upload.
            Thread.sleep(forTimeInterval: 14)
            note("after 14 s away, \(LocalState.filesSetAside().count) files were still set aside")
        }
        step("back") {
            app.activate()
            // The save may still be running, with the editor up, or done, with the vault locked behind it.
            if !waitUntil(150, { self.currentScreen() != nil }) {
                dumpTree(app, as: "no-screen-after-return")
                XCTFail("the app showed neither the unlock screen nor the vault within 150 s of coming back")
            }
            let came = currentScreen()
            note("the app came back on the \(came?.rawValue ?? "unknown") screen")
            reachVaultAnyWay()
        }
        step("note-saved-once-with-its-files") {
            let rows = app.descendants(matching: .any).matching(identifier: "vault.item." + note)
            if !findInVault(note, timeout: 150) {
                dumpTree(app, as: "note-not-saved")
                XCTFail("\(note) is not in the vault after the app came back. The vault says: \(vaultWords())")
            }
            let cutShort = app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'cut short'")).firstMatch
            if cutShort.exists {
                note("the vault says: \(cutShort.label)")
            }
            XCTAssertEqual(rows.count, 1, "\(note) is in the vault \(rows.count) times")
            XCTAssertTrue(waitUntil(60) { LocalState.filesSetAside().isEmpty }, "files of the save are still set aside on the device after it was done: \(LocalState.filesSetAside())")
            openAnyItem(note)
            for file in files {
                XCTAssertTrue(scrollToComfort(detailFile(file.name)), "\(file.name) is not among the item's files")
            }
        }
        for file in files { FilesApp.remove(file.name) }
        step("a-file-saved-back-is-the-file-added") {
            let file = files[1]
            openFile(file.name)
            XCTAssertEqual(previewRefusal(), "andvari can't show this kind of file. Save it to Files to open it in another app.", "a file of no kind andvari shows does not say so")
            let back = saveOpenFileToFiles(file.name)
            XCTAssertEqual(back.map(Self.digest), Self.digest(file.data), "the file saved to Files (\(back?.count ?? 0) bytes) is not the file that was added (\(file.data.count) bytes)")
            closeFile(file.name)
        }
    }

    // MARK: - The editor's files

    /// The editor's Add a file menu, scrolled to and opened: its entries are then on screen. The menu is the label at
    /// the row's leading end; the rest of the row is not part of it, so a tap on the row's middle opens nothing.
    private func openAddFileMenu() {
        let row = app.buttons["editor.add-file"]
        if !scrollFormTo(row) {
            dumpTree(app, as: "no-add-a-file")
            XCTFail("the editor has no Add a file to tap")
        }
        let label = row.buttons.firstMatch
        let entry = app.buttons["Choose a file"]
        for _ in 0..<3 where !entry.exists {
            if label.exists {
                label.tap()
            } else {
                row.coordinate(withNormalizedOffset: CGVector(dx: 0.15, dy: 0.5)).tap()
            }
            _ = waitUntil(4) { entry.exists }
        }
        require(entry, "the Add a file menu's entries", timeout: 5)
    }

    /// The Add a file menu's [entry], chosen.
    private func openAddMenu(_ entry: String) {
        openAddFileMenu()
        let item = app.buttons[entry]
        require(item, "\(entry) in the Add a file menu", timeout: 5)
        item.tap()
    }

    /// Add [names] from On My iPhone with the editor's Choose a file, in as many goes as the picker needs, and wait
    /// until the editor lists each.
    private func addFromFiles(_ names: [String], tag: String, timeout: TimeInterval = 90) {
        var remaining = names
        var round = 0
        while !remaining.isEmpty {
            round += 1
            openAddMenu("Choose a file")
            let chosen = chooseInFilePicker(remaining, tag: "\(tag)-\(round)")
            if chosen.isEmpty {
                XCTFail("the file picker never showed \(remaining[0]) in On My iPhone. The simulator's folder holds \(FilesApp.files())")
                return
            }
            for name in chosen where !waitUntil(timeout, { self.app.buttons["Remove \(name)"].exists }) {
                dumpTree(app, as: "file-not-added")
                XCTFail("\(name) was chosen but is not among the editor's files. The editor says: \(editorWords())")
                return
            }
            remaining.removeAll { chosen.contains($0) }
        }
    }

    /// A new note's editor with its Name typed. The name goes in first, while its field is on screen; Return puts the
    /// keyboard away, so the form below it can be scrolled.
    private func openNewNote(_ name: String) {
        openNewItemEditor("New note")
        require(app.navigationBars["New note"], "the note editor")
        enter(name + "\n", into: app.textFields["Name"], what: "the Name field")
        _ = waitUntil(5) { !self.app.keyboards.firstMatch.exists }
    }

    /// Save the note with its files (they go up with it) and find it in the vault.
    private func saveNote(_ name: String) {
        saveEditor("New note", timeout: 90)
        requireInVault(name)
    }

    /// What the editor says about its files: a refusal, or that it is still adding or sending.
    private func editorWords() -> String {
        screenWords(containing: ["could not", "can't", "too large", "larger", "Adding", "Sending"])
    }

    private func vaultWords() -> String {
        screenWords(containing: ["files", "saved", "could not", "can't"])
    }

    // MARK: - The item's files

    /// A file's row in the open item: its button reads the file's name and size.
    private func detailFile(_ name: String) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "identifier == 'detail.file' AND label CONTAINS %@", name)).firstMatch
    }

    /// Open one of the item's files and wait until it is decrypted (its Save to Files can then be used).
    private func openFile(_ name: String) {
        let row = detailFile(name)
        if !scrollToComfort(row) {
            dumpTree(app, as: "no-file-row")
            XCTFail("\(name) is not among the item's files")
        }
        row.tap()
        require(app.navigationBars[name], "the opened file \(name)", timeout: 20)
        let save = element("file.save")
        if !waitUntil(90, { save.exists && save.isEnabled }) {
            dumpTree(app, as: "file-not-opened")
            XCTFail("\(name) did not open: \(previewWords())")
        }
    }

    private func closeFile(_ name: String) {
        let bar = app.navigationBars[name]
        bar.buttons["Done"].tap()
        _ = waitUntil(10) { !bar.exists }
    }

    /// What the open file's sheet says instead of showing it, nil when it says none of those things.
    private func previewRefusal() -> String? {
        for refusal in ["This file can't be opened.", "andvari can't show this kind of file. Save it to Files to open it in another app.", "This image can't be shown."] where app.staticTexts[refusal].exists {
            return refusal
        }
        return nil
    }

    private func previewWords() -> String {
        screenWords(containing: ["can't", "could not", "Opening", "Saved"])
    }

    /// Save the open file to Files, and read back what landed in On My iPhone. Nil when nothing new landed there.
    private func saveOpenFileToFiles(_ name: String) -> Data? {
        let before = Set(FilesApp.files())
        element("file.save").tap()
        saveInFilePicker(tag: (name as NSString).pathExtension)
        if !waitUntil(20, { self.app.staticTexts["Saved to Files."].exists }) {
            dumpTree(app, as: "not-saved-to-files")
            XCTFail("the opened file does not say it was saved to Files: \(previewWords())")
        }
        var landed: String?
        _ = waitUntil(15) {
            landed = FilesApp.files().first { !before.contains($0) }
            return landed != nil
        }
        guard let landed else {
            XCTFail("the file is said to be saved, but nothing new is in On My iPhone, which holds \(FilesApp.files())")
            return nil
        }
        note("Save to Files wrote \(landed)")
        return FilesApp.read(landed)
    }

    // MARK: - The files the tests add

    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func random(_ count: Int) -> Data {
        var data = Data(count: count)
        data.withUnsafeMutableBytes { buffer in
            if let base = buffer.baseAddress { arc4random_buf(base, count) }
        }
        return data
    }

    /// A one-page PDF that says [words].
    private static func pdf(saying words: String) -> Data {
        UIGraphicsPDFRenderer(bounds: CGRect(x: 0, y: 0, width: 320, height: 200)).pdfData { context in
            context.beginPage()
            (words as NSString).draw(at: CGPoint(x: 20, y: 40), withAttributes: [.font: UIFont.systemFont(ofSize: 14)])
        }
    }

    /// A small PNG: a black square on orange.
    private static func png() -> Data {
        let size = CGSize(width: 120, height: 80)
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        return UIGraphicsImageRenderer(size: size, format: format).pngData { context in
            UIColor.orange.setFill()
            context.fill(CGRect(origin: .zero, size: size))
            UIColor.black.setFill()
            context.fill(CGRect(x: 20, y: 20, width: 30, height: 30))
        }
    }
}
