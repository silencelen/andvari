import XCTest

/// Getting logins in and out: another password manager's CSV export imported from Files, what vault health then counts,
/// the vault exported as a CSV and read back, and a backup under a passphrase. The files are in the simulator's On My
/// iPhone: the runner puts the CSV there and reads what the app wrote (FilesApp).
final class T8TransferTests: UITestCase {
    private typealias Login = (name: String, url: String, user: String, password: String)

    private let stamp = Int(Date().timeIntervalSince1970) % 100000

    /// A Chrome export of three logins: the screen says where it is from and what it would add, the import adds them,
    /// and one with a comma and quotes in its password reads as it was in the file. The same file again adds nothing:
    /// all three are already in the vault.
    func test01_CsvImportAddsItsLoginsOnce() {
        let file = "uitest-import-\(stamp).csv"
        let logins: [Login] = [
            (name: "Imported A \(stamp)", url: "https://imported-a.example.com/login", user: "ann", password: "first-Imp0rted-pass"),
            (name: "Imported B \(stamp)", url: "https://imported-b.example.com/", user: "ben@example.com", password: "second-Imp0rted-pass"),
            (name: "Imported C \(stamp)", url: "https://imported-c.example.com/", user: "cy", password: "a,b \"c\" 'd' -- 9"),
        ]
        step("csv-in-on-my-iphone") {
            requireFilesStorage()
            XCTAssertTrue(FilesApp.put(file, chromeCsv(logins)), "\(file) could not be written into On My iPhone")
        }
        step("file-chosen-and-read") {
            freshVault()
            openImport(of: file, tag: "first")
            XCTAssertTrue(says("Chrome or another Chromium browser").exists, "the screen does not say the file is a Chrome export: \(importWords())")
            XCTAssertTrue(app.staticTexts["3 items to import"].exists, "the screen does not say 3 items would be imported: \(importWords())")
        }
        step("imported") {
            let start = app.buttons["Import 3 items"]
            XCTAssertTrue(scrollToComfort(start, lowest: 0.93), "the screen offers no Import 3 items: \(importWords())")
            start.tap()
            let added = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Added 3 items to '")).firstMatch
            if !waitUntil(90, { added.exists }) {
                dumpTree(app, as: "import-not-done")
                XCTFail("the import did not say it added 3 items: \(importWords())")
            }
            note(added.label)
            closeImport()
        }
        step("logins-in-the-vault-as-in-the-file") {
            for login in logins {
                requireInVault(login.name)
            }
            let tricky = logins[2]
            XCTAssertEqual(revealedPassword(of: tricky.name), tricky.password, "the imported password is not the file's")
            XCTAssertEqual(element("detail.username").value as? String, tricky.user, "the imported username is not the file's")
            app.navigationBars.buttons.firstMatch.tap()
        }
        step("same-file-again-adds-nothing") {
            _ = waitUntil(10) { self.safelyHittable(self.settingsButton) }
            openImport(of: file, tag: "again")
            XCTAssertTrue(app.staticTexts["0 items to import"].exists, "the same file again would still add something: \(importWords())")
            XCTAssertTrue(says("Already in the vault, not imported: 3").exists, "the screen does not say the three are already in the vault: \(importWords())")
            let cancel = app.buttons["Cancel"]
            scrollToComfort(cancel, lowest: 0.93)
            cancel.tap()
            leaveSettingsScreen()
        }
        FilesApp.remove(file)
    }

    /// Two logins imported with one weak password between them: vault health counts two more logins, two more weak and
    /// two more reused than before, and says of each that it is reused in one other login.
    func test02_VaultHealthCountsWhatWasImported() {
        let file = "uitest-weak-\(stamp).csv"
        let logins: [Login] = [
            (name: "Weak A \(stamp)", url: "https://weak-a.example.com/", user: "wanda", password: "password1"),
            (name: "Weak B \(stamp)", url: "https://weak-b.example.com/", user: "wes", password: "password1"),
        ]
        var before: [String: Int] = [:]
        step("health-before") {
            freshVault()
            before = healthCounts()
            XCTAssertNotNil(before["Logins"], "vault health shows no count of logins")
            leaveSettingsScreen()
        }
        step("two-weak-logins-imported") {
            requireFilesStorage()
            XCTAssertTrue(FilesApp.put(file, chromeCsv(logins)), "\(file) could not be written into On My iPhone")
            _ = waitUntil(10) { self.safelyHittable(self.settingsButton) }
            openImport(of: file, tag: "weak")
            let start = app.buttons["Import 2 items"]
            XCTAssertTrue(scrollToComfort(start, lowest: 0.93), "the screen offers no Import 2 items: \(importWords())")
            start.tap()
            let added = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Added 2 items to '")).firstMatch
            if !waitUntil(90, { added.exists }) {
                dumpTree(app, as: "import-not-done")
                XCTFail("the import did not say it added 2 items: \(importWords())")
            }
            closeImport()
            FilesApp.remove(file)
        }
        step("health-after") {
            _ = waitUntil(10) { self.safelyHittable(self.settingsButton) }
            let after = healthCounts()
            for tile in ["Logins", "Weak", "Reused"] {
                XCTAssertEqual(after[tile], before[tile].map { $0 + 2 }, "vault health's \(tile) went from \(String(describing: before[tile])) to \(String(describing: after[tile])) for two imported logins that share a weak password")
            }
        }
        step("each-said-to-be-reused") {
            for login in logins {
                let line = healthLine(of: login.name)
                XCTAssertTrue(line?.contains("reused in 1 other login") == true, "vault health says of \(login.name): \(line ?? "nothing")")
            }
            leaveSettingsScreen()
        }
    }

    /// A login imported, then the vault exported as a CSV into On My iPhone: the screen names the file it saved, the
    /// file has the logins the screen counted, and the imported login is in it exactly as it went in.
    func test03_CsvExportHoldsWhatWasImported() {
        let file = "uitest-roundtrip-\(stamp).csv"
        let marker = "uitest-folder-\(stamp).txt"
        let login: Login = (name: "Round Trip \(stamp)", url: "https://round-trip.example.com/login", user: "rita", password: "p,w \"q\" 'x' -- 9")
        step("login-imported") {
            requireFilesStorage()
            XCTAssertTrue(FilesApp.put(file, chromeCsv([login])), "\(file) could not be written into On My iPhone")
            freshVault()
            openImport(of: file, tag: "roundtrip")
            let start = app.buttons["Import 1 item"]
            XCTAssertTrue(scrollToComfort(start, lowest: 0.93), "the screen offers no Import 1 item: \(importWords())")
            start.tap()
            let added = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Added 1 item to '")).firstMatch
            if !waitUntil(90, { added.exists }) {
                dumpTree(app, as: "import-not-done")
                XCTFail("the import did not say it added 1 item: \(importWords())")
            }
            closeImport()
            FilesApp.remove(file)
        }
        var written = 0
        step("export-screen") {
            _ = waitUntil(10) { self.safelyHittable(self.settingsButton) }
            openExport("Export for another password manager…", title: "Export as CSV")
            let count = app.staticTexts.matching(NSPredicate(format: "label ENDSWITH 'logins are written.' OR label ENDSWITH 'login is written.'")).firstMatch
            require(count, "how many logins the file would hold", timeout: 60)
            written = Int(count.label.prefix { $0.isNumber }) ?? 0
            XCTAssertGreaterThan(written, 0, "the export screen counts no logins: \(count.label)")
            // A login whose field starts like a formula (a generated password can) asks for a tick first.
            let tick = app.switches.matching(NSPredicate(format: "label CONTAINS 'a spreadsheet would run these cells as formulas'")).firstMatch
            if tick.exists {
                scrollToComfort(tick, lowest: 0.93)
                if !isOn(tick) { flip(tick) }
                XCTAssertTrue(waitUntil(5) { self.isOn(tick) }, "the formula acknowledgement could not be ticked")
            }
        }
        var saved = ""
        step("saved-into-on-my-iphone") {
            XCTAssertTrue(FilesApp.put(marker, Data("the folder the UI tests export into\n".utf8)), "\(marker) could not be written into On My iPhone")
            saved = exportIntoOnMyIPhone(marker: marker, tag: "csv")
            XCTAssertTrue(saved.hasSuffix(".csv"), "the export is not named as a CSV: \(saved)")
        }
        step("file-holds-the-logins") {
            guard let data = FilesApp.read(saved), let text = String(data: data, encoding: .utf8) else {
                XCTFail("\(saved) is not in On My iPhone, which holds \(FilesApp.files())")
                return
            }
            let records = csvRecords(text)
            XCTAssertEqual(records.first, ["name", "url", "username", "password", "note", "totp"], "the file's first line is not the header")
            XCTAssertEqual(records.count - 1, written, "the file holds \(records.count - 1) logins, the screen said \(written)")
            let mine = records.filter { $0.first == login.name }
            XCTAssertEqual(mine.count, 1, "\(login.name) is in the file \(mine.count) times")
            if let record = mine.first, record.count >= 4 {
                XCTAssertEqual(record[1], login.url, "the exported website is not the one imported")
                XCTAssertEqual(record[2], login.user, "the exported username is not the one imported")
                XCTAssertEqual(record[3], login.password, "the exported password is not the one imported")
            }
            // The export is every password in plain text: it does not stay in the simulator's Files.
            FilesApp.remove(saved)
            FilesApp.remove(marker)
            leaveSettingsScreen()
        }
    }

    /// A backup under a passphrase typed a key at a time, twice: the file saved into On My iPhone is an andvari backup
    /// and holds no password in plain text.
    func test04_BackupIsSavedEncrypted() {
        let marker = "uitest-folder-\(stamp).txt"
        let passphrase = "x7#Qm-pL2!vR9zKd"
        step("backup-screen") {
            requireFilesStorage()
            freshVault()
            openExport("Back up…", title: "Back up")
            let count = app.staticTexts.matching(NSPredicate(format: "label ENDSWITH 'items are backed up.' OR label ENDSWITH 'item is backed up.'")).firstMatch
            require(count, "how many items the backup would hold", timeout: 60)
        }
        step("passphrase-typed-twice") {
            let first = app.secureTextFields["field.backup-passphrase"]
            let again = app.secureTextFields["field.backup-passphrase-again"]
            XCTAssertTrue(scrollFormTo(first), "the passphrase field could not be brought on screen")
            var typed = typeKeyByKey(passphrase, into: first, what: "the backup passphrase field")
            XCTAssertEqual(typed, passphrase.count, "the backup passphrase field let go of the keyboard after \(typed) of \(passphrase.count) characters")
            if let dots = hiddenLength(of: first) {
                XCTAssertEqual(dots, passphrase.count, "the backup passphrase field shows \(dots) dots for \(passphrase.count) characters typed")
            }
            XCTAssertTrue(scrollFormTo(again), "the second passphrase field could not be brought on screen")
            typed = typeKeyByKey(passphrase, into: again, what: "the second backup passphrase field")
            XCTAssertEqual(typed, passphrase.count, "the second backup passphrase field let go of the keyboard after \(typed) of \(passphrase.count) characters")
            // Return puts the keyboard away.
            again.typeText("\n")
            _ = waitUntil(5) { !self.app.keyboards.firstMatch.exists }
            XCTAssertFalse(app.staticTexts["The passphrases don't match."].exists, "the two passphrases, typed the same, are said to differ")
            let weak = app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'needs at least'")).firstMatch
            XCTAssertFalse(weak.exists, "the passphrase is said to be too weak: \(weak.exists ? weak.label : "")")
        }
        var saved = ""
        step("saved-into-on-my-iphone") {
            XCTAssertTrue(FilesApp.put(marker, Data("the folder the UI tests export into\n".utf8)), "\(marker) could not be written into On My iPhone")
            saved = exportIntoOnMyIPhone(marker: marker, tag: "backup", timeout: 180)
        }
        step("file-is-an-encrypted-backup") {
            guard let data = FilesApp.read(saved) else {
                XCTFail("\(saved) is not in On My iPhone, which holds \(FilesApp.files())")
                return
            }
            XCTAssertEqual(String(data: data.prefix(8), encoding: .utf8), "ANDVBK01", "the file does not start as an andvari backup")
            XCTAssertGreaterThan(data.count, 200, "the backup is only \(data.count) bytes")
            for secret in [Fixture.sitePassword, Fixture.siteItem, Fixture.cardNumber] {
                XCTAssertNil(data.range(of: Data(secret.utf8)), "the backup holds “\(secret)” in plain text")
            }
            FilesApp.remove(saved)
            FilesApp.remove(marker)
            leaveSettingsScreen()
        }
    }

    // MARK: - Import

    /// A Chrome export: its header, then a line a login. A field with a comma, a quote or a line break is quoted.
    private func chromeCsv(_ logins: [Login]) -> Data {
        func cell(_ value: String) -> String {
            guard value.contains(where: { ",\"\n\r".contains($0) }) else { return value }
            return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        var lines = ["name,url,username,password,note"]
        for login in logins {
            lines.append([login.name, login.url, login.user, login.password, ""].map(cell).joined(separator: ","))
        }
        return Data((lines.joined(separator: "\n") + "\n").utf8)
    }

    /// Settings > Import passwords with [file] chosen from On My iPhone: the screen then says what the file holds.
    private func openImport(of file: String, tag: String) {
        openSettings()
        settingsControl("Import passwords", "Import passwords in Settings").tap()
        let choose = app.buttons["Choose a CSV file…"]
        require(choose, "Choose a CSV file… on the import screen", timeout: 20)
        choose.tap()
        let chosen = chooseInFilePicker([file], tag: "import-" + tag)
        XCTAssertEqual(chosen, [file], "the file picker never showed \(file) in On My iPhone, which holds \(FilesApp.files())")
        let holds = app.staticTexts.matching(NSPredicate(format: "label ENDSWITH 'to import'")).firstMatch
        if !waitUntil(30, { holds.exists }) {
            dumpTree(app, as: "import-not-read")
            XCTFail("the import screen did not say what the file holds: \(importWords())")
        }
    }

    /// The import's Done, then out of Settings to the vault.
    private func closeImport() {
        let done = app.buttons.matching(NSPredicate(format: "label == 'Done' AND identifier != 'settings.done'"))
        if let button = firstHittable(done) {
            button.tap()
        } else {
            dumpTree(app, as: "no-import-done")
            XCTFail("the import screen has no Done after the import")
        }
        leaveSettingsScreen()
    }

    private func importWords() -> String {
        screenWords(containing: ["import", "Exported", "Added", "Already", "couldn't", "isn't", "larger", "Retry"])
    }

    // MARK: - Vault health

    /// Settings > Vault health, and the numbers on its tiles by their labels ("Logins", "Weak", "Reused"). The screen is
    /// left open.
    private func healthCounts() -> [String: Int] {
        openSettings()
        settingsControl("Vault health", "Vault health in Settings").tap()
        let logins = app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH 'Logins: '")).firstMatch
        require(logins, "vault health's count of logins", timeout: 30)
        var counts: [String: Int] = [:]
        for label in ["Logins", "Weak", "Reused", "Duplicates", "Unchecked", "Failing"] {
            let tile = app.descendants(matching: .any).matching(NSPredicate(format: "label BEGINSWITH %@", label + ": ")).firstMatch
            guard tile.exists else { continue }
            counts[label] = Int(tile.label.dropFirst(label.count + 2).prefix { $0.isNumber })
        }
        note("vault health counts " + counts.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", "))
        return counts
    }

    /// What vault health's Passwords list says of the login [name]: its "Strength: …" line.
    private func healthLine(of name: String) -> String? {
        let title = app.staticTexts[name]
        if !scrollToComfort(title, lowest: 0.93) {
            dumpTree(app, as: "no-health-row")
            return nil
        }
        // The row reads as one element (name, strength, breaches) or as its three lines.
        let whole = app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@ AND label CONTAINS 'Strength:'", name)).firstMatch
        if whole.exists { return whole.label }
        let lines = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Strength:'"))
        guard let top = try? title.snapshot().frame else { return nil }
        for index in 0..<lines.count {
            let line = lines.element(boundBy: index)
            guard line.exists, let at = try? line.snapshot().frame else { continue }
            // Its own strength line is the one right under the name.
            if at.minY >= top.minY && at.minY < top.maxY + 30 { return line.label }
        }
        dumpTree(app, as: "no-health-line")
        return nil
    }

    // MARK: - Export

    /// Settings > Back up and export > [entry], whose screen is titled [title].
    private func openExport(_ entry: String, title: String) {
        openSettings()
        settingsControl("Back up and export", "Back up and export in Settings").tap()
        let link = app.buttons[entry]
        require(link, "\(entry) under Back up and export", timeout: 20)
        link.tap()
        require(app.navigationBars[title], "the \(title) screen", timeout: 20)
    }

    /// Choose a folder…, On My iPhone in the picker, and the name of the file the screen then says it saved there.
    private func exportIntoOnMyIPhone(marker: String, tag: String, timeout: TimeInterval = 60) -> String {
        let choose = app.buttons["Choose a folder…"]
        if !scrollToComfort(choose, lowest: 0.93) {
            dumpTree(app, as: "no-choose-a-folder")
            XCTFail("the export screen has no Choose a folder… to tap")
        }
        XCTAssertTrue(choose.isEnabled, "Choose a folder… is not offered: \(exportWords())")
        choose.tap()
        chooseOnMyIPhoneFolder(marker: marker, tag: "export-" + tag)
        let done = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH 'Saved “'")).firstMatch
        if !waitUntil(timeout, { done.exists }) {
            dumpTree(app, as: "export-not-saved")
            XCTFail("the export screen did not say it saved the file: \(exportWords())")
            return ""
        }
        note(done.label)
        // Saved “name” to folder: …
        let line = done.label
        guard let open = line.firstIndex(of: "“"), let close = line.firstIndex(of: "”"), open < close else {
            XCTFail("the export screen's line names no file: \(line)")
            return ""
        }
        return String(line[line.index(after: open)..<close])
    }

    private func exportWords() -> String {
        screenWords(containing: ["Saved", "Nothing", "couldn't", "did not", "written", "Tick", "passphrase", "locked"])
    }

    /// The records of a CSV text (RFC 4180: quoted fields, doubled quotes, line breaks inside quotes).
    private func csvRecords(_ text: String) -> [[String]] {
        var records: [[String]] = []
        var record: [String] = []
        var field = ""
        var quoted = false
        var index = text.startIndex
        while index < text.endIndex {
            let character = text[index]
            index = text.index(after: index)
            if quoted {
                if character != "\"" {
                    field.append(character)
                } else if index < text.endIndex, text[index] == "\"" {
                    field.append("\"")
                    index = text.index(after: index)
                } else {
                    quoted = false
                }
            } else if character == "\"" {
                quoted = true
            } else if character == "," {
                record.append(field)
                field = ""
            } else if character == "\r\n" || character == "\n" || character == "\r" {
                record.append(field)
                field = ""
                records.append(record)
                record = []
            } else {
                field.append(character)
            }
        }
        if !field.isEmpty || !record.isEmpty {
            record.append(field)
            records.append(record)
        }
        return records
    }

    // MARK: - Shared

    /// Something on screen that says [text], in its label or its value (a labelled row carries its value apart).
    private func says(_ text: String) -> XCUIElement {
        app.descendants(matching: .any).matching(NSPredicate(format: "label CONTAINS %@ OR value CONTAINS %@", text, text)).firstMatch
    }

    /// From a screen under Settings back to the vault: back until Settings' own screen, then its Done.
    private func leaveSettingsScreen() {
        let done = element("settings.done")
        for _ in 0..<4 where !done.exists {
            app.navigationBars.buttons.element(boundBy: 0).tap()
            _ = waitUntil(4) { done.exists }
        }
        require(done, "Settings' Done", timeout: 10)
        done.tap()
        _ = waitUntil(10) { !done.exists }
    }
}
