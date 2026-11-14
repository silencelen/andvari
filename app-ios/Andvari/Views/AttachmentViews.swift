import AndvariCore
import ImageIO
import PDFKit
import PhotosUI
import SwiftUI
import UIKit
import UniformTypeIdentifiers
import VisionKit

// MARK: - Rows

/// One file: what kind it is, its name and its size.
struct FileRow: View {
    let name: String
    let size: Int64

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: FileKind.symbol(for: name))
                .foregroundStyle(Palette.goldText)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(name)
                    .foregroundStyle(Palette.ink)
                    .lineLimit(2)
                Text(ByteCountFormatter.string(fromByteCount: size, countStyle: .file))
                    .font(.footnote)
                    .foregroundStyle(Palette.inkDim)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

/// A file of an item, as a sheet opens it.
struct OpenedFile: Identifiable {
    let id: String
    let name: String
    let size: Int64

    init(_ file: AttachmentView) {
        id = file.id
        name = file.name
        size = file.size
    }
}

// MARK: - The detail's files

/// The item's files; one opens in a sheet, from memory.
struct AttachmentsSection: View {
    let files: [AttachmentView]
    let open: (AttachmentView) -> Void

    var body: some View {
        Section("Files") {
            ForEach(files, id: \.id) { file in
                Button {
                    open(file)
                } label: {
                    FileRow(name: file.name, size: file.size)
                }
                .accessibilityIdentifier("detail.file")
            }
        }
        .listRowBackground(Palette.raised)
    }
}

/// One file, decrypted into memory and shown there: an image, a PDF or text. Nothing is written for it, and there is no
/// share sheet; Save to Files hands the bytes to the system's file exporter.
struct AttachmentPreview: View {
    let itemId: String
    let file: OpenedFile

    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var data: Data?
    @State private var message: String?
    @State private var loading = true
    @State private var exporting = false
    @State private var saved = false

    var body: some View {
        NavigationStack {
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Palette.background)
                .navigationTitle(file.name)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Done") {
                            dismiss()
                        }
                    }
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            exporting = true
                        } label: {
                            Label("Save to Files", systemImage: "square.and.arrow.down")
                        }
                        .disabled(data == nil)
                        .accessibilityIdentifier("file.save")
                    }
                }
                .toolbarBackground(Palette.background, for: .navigationBar)
        }
        .fileExporter(isPresented: $exporting, document: data.map { MemoryFile(data: $0) }, contentType: .data, defaultFilename: file.name) { result in
            // The exporter writes the bytes to a file of its own for the system's picker; none is left behind.
            TemporaryFiles.clear()
            switch result {
            case .success:
                saved = true
            case .failure(let error):
                if (error as? CocoaError)?.code != .userCancelled {
                    message = "The file could not be saved to Files."
                }
            }
        }
        .task {
            await load()
        }
        .onDisappear {
            data = nil
        }
    }

    @ViewBuilder private var content: some View {
        if loading {
            ProgressView("Opening…")
                .tint(Palette.gold)
        } else if let data {
            VStack(spacing: 0) {
                FilePreview(name: file.name, data: data)
                if saved {
                    Text("Saved to Files.")
                        .font(.footnote)
                        .foregroundStyle(Palette.inkDim)
                        .padding(8)
                }
                if let message {
                    InlineMessage(text: message)
                        .padding(8)
                }
            }
        } else {
            VStack(spacing: 12) {
                Image(systemName: "doc")
                    .font(.largeTitle)
                    .foregroundStyle(Palette.inkFaint)
                Text(message ?? "This file can't be opened.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(Palette.ink)
            }
            .padding(24)
        }
    }

    private func load() async {
        guard loading else { return }
        let opened = await model.openAttachment(itemId: itemId, attachmentId: file.id)
        loading = false
        guard let opened else {
            dismiss()
            return
        }
        if let bytes = opened.data {
            data = bytes
        } else if let error = opened.error {
            message = error
        } else {
            dismiss() // the vault locked meanwhile
        }
    }
}

/// Bytes the file exporter writes where the person chooses.
struct MemoryFile: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }

    let data: Data

    init(data: Data) {
        self.data = data
    }

    init(configuration: ReadConfiguration) throws {
        throw CocoaError(.featureUnsupported)
    }

    func fileWrapper(configuration: WriteConfiguration) -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

/// The app's temporary folder: the file exporter stages what it writes there, and the document camera may leave its
/// pages there. It is emptied at launch, when an export ends, after a scan, when the app leaves the foreground and when
/// the vault locks; and what is created there is protected until the device is next unlocked (round-9 review 5).
enum TemporaryFiles {
    /// Empties the temporary folder and Caches (round-10 review 8): whatever an export, a scan or the system's pickers
    /// staged there goes, at launch, on leaving the app, on a lock, and after each export and scan. The system's own
    /// app-switcher snapshots stay (the privacy cover is what they show); the app keeps nothing of its own in either
    /// folder, and its HTTP client writes no cache.
    static func clear() {
        let fm = FileManager.default
        for dir in folders(fm) {
            for url in (try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? [] where url.lastPathComponent != "Snapshots" {
                try? fm.removeItem(at: url)
            }
        }
    }

    private static func folders(_ fm: FileManager) -> [URL] {
        var dirs = [fm.temporaryDirectory]
        if let caches = fm.urls(for: .cachesDirectory, in: .userDomainMask).first {
            dirs.append(caches)
        }
        return dirs
    }

    /// Files created in the temporary folder and in Caches inherit the folder's protection: complete, readable only
    /// while the device is unlocked.
    static func protect() {
        let fm = FileManager.default
        for dir in folders(fm) {
            try? fm.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: dir.path)
        }
    }
}

// MARK: - Showing a file

/// What a file can be shown as.
enum FileKind {
    case pdf
    case image
    case text
    case other

    /// The most text shown; a longer file shows its beginning.
    static let textLimit = 1_000_000

    init(name: String, data: Data) {
        let type = UTType(filenameExtension: (name as NSString).pathExtension)
        if data.starts(with: [0x25, 0x50, 0x44, 0x46]) || type?.conforms(to: .pdf) == true {
            self = .pdf
        } else if type?.conforms(to: .image) == true || ImagePreview.readable(data) {
            self = .image
        } else if type?.conforms(to: .text) == true {
            self = .text
        } else {
            self = .other
        }
    }

    static func symbol(for name: String) -> String {
        let type = UTType(filenameExtension: (name as NSString).pathExtension)
        if type?.conforms(to: .pdf) == true { return "doc.richtext" }
        if type?.conforms(to: .image) == true { return "photo" }
        if type?.conforms(to: .movie) == true { return "film" }
        if type?.conforms(to: .text) == true { return "doc.text" }
        return "doc"
    }
}

struct FilePreview: View {
    let name: String
    let data: Data

    var body: some View {
        switch FileKind(name: name, data: data) {
        case .pdf:
            PDFPreview(data: data)
        case .image:
            ImagePreview(data: data)
        case .text:
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(String(decoding: data.prefix(FileKind.textLimit), as: UTF8.self))
                        .font(.body.monospaced())
                        .foregroundStyle(Palette.ink)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    if data.count > FileKind.textLimit {
                        Text("This is the beginning of the file. Save it to Files to see the rest.")
                            .font(.footnote)
                            .foregroundStyle(Palette.inkDim)
                    }
                }
                .padding(16)
            }
        case .other:
            VStack(spacing: 12) {
                Image(systemName: "doc")
                    .font(.largeTitle)
                    .foregroundStyle(Palette.inkFaint)
                Text("andvari can't show this kind of file. Save it to Files to open it in another app.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(Palette.ink)
            }
            .padding(24)
        }
    }
}

/// A PDF, from memory.
struct PDFPreview: UIViewRepresentable {
    let data: Data

    func makeUIView(context: Context) -> PDFView {
        let view = PDFView()
        view.autoScales = true
        view.displayMode = .singlePageContinuous
        view.backgroundColor = .clear
        view.document = PDFDocument(data: data)
        return view
    }

    func updateUIView(_ view: PDFView, context: Context) {}
}

/// An image, decoded at most [maxPixels] on its long side so a large photo does not take its full size in memory.
struct ImagePreview: View {
    let data: Data

    static let maxPixels = 3000

    @State private var image: UIImage?
    @State private var failed = false
    @State private var scale: CGFloat = 1
    @State private var settledScale: CGFloat = 1

    var body: some View {
        Group {
            if let image {
                GeometryReader { geo in
                    ScrollView([.horizontal, .vertical]) {
                        Image(uiImage: image)
                            .resizable()
                            .scaledToFit()
                            .frame(width: geo.size.width * scale, height: geo.size.height * scale)
                    }
                    .gesture(
                        MagnifyGesture()
                            .onChanged { value in
                                scale = min(max(settledScale * value.magnification, 1), 6)
                            }
                            .onEnded { _ in
                                settledScale = scale
                            }
                    )
                }
                .accessibilityLabel("Image")
            } else if failed {
                Text("This image can't be shown.")
                    .foregroundStyle(Palette.ink)
            } else {
                ProgressView()
                    .tint(Palette.gold)
            }
        }
        .task {
            let bytes = data
            let decoded = await Task.detached(priority: .userInitiated) { ImagePreview.downsampled(bytes) }.value
            image = decoded
            failed = decoded == nil
        }
    }

    private static let noCache: [CFString: Any] = [kCGImageSourceShouldCache: false]

    static func readable(_ data: Data) -> Bool {
        guard let source = CGImageSourceCreateWithData(data as CFData, noCache as CFDictionary) else { return false }
        return CGImageSourceGetType(source) != nil && CGImageSourceGetCount(source) > 0
    }

    static func downsampled(_ data: Data) -> UIImage? {
        guard let source = CGImageSourceCreateWithData(data as CFData, noCache as CFDictionary) else { return nil }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
            kCGImageSourceThumbnailMaxPixelSize: maxPixels,
        ]
        guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else { return nil }
        return UIImage(cgImage: image)
    }
}

// MARK: - The editor's files

/// What an editor's Files section is doing: which picker is up, and the files being read and added.
@MainActor
final class FileAdding: ObservableObject {
    @Published var choosingFiles = false
    @Published var choosingPhotos = false
    @Published var scanning = false
    @Published var photoItems: [PhotosPickerItem] = []
    @Published private(set) var working = false
    @Published var message: String?

    /// Files from the Files app: each is sized first, and read (never past the limits) only when it fits.
    func addFiles(_ result: Result<[URL], Error>, model: AppModel) {
        message = nil
        guard case .success(let urls) = result else {
            message = "The file could not be opened."
            return
        }
        guard !urls.isEmpty else { return }
        working = true
        Task {
            defer { working = false }
            for url in urls {
                let scoped = url.startAccessingSecurityScopedResource()
                defer {
                    if scoped {
                        url.stopAccessingSecurityScopedResource()
                    }
                }
                let name = url.lastPathComponent
                if let size = FileReading.size(url), let refusal = model.attachmentRefusal(size: size) {
                    message = "“\(name)”: \(refusal)"
                    continue
                }
                let limit = model.attachmentReadLimit()
                let read = await Task.detached(priority: .userInitiated) { FileReading.read(url, limit: limit) }.value
                await take(read, name: name, model: model)
            }
        }
    }

    /// Photos and videos from the photo picker (no access to the library is asked for): each is sized before it is read.
    func addPhotos(_ items: [PhotosPickerItem], model: AppModel) {
        guard !items.isEmpty else { return }
        photoItems = []
        message = nil
        working = true
        Task {
            defer { working = false }
            for item in items {
                ReadLimit.current = model.attachmentReadLimit()
                guard let picked = try? await item.loadTransferable(type: PickedMedia.self) else {
                    message = "That photo or video could not be read."
                    continue
                }
                await take(picked.read, name: picked.name, model: model)
            }
        }
    }

    /// The scanner closed on a scan: its pages are being made ready.
    func preparingScan() {
        message = nil
        working = true
    }

    /// A scan's pages, made into one PDF in memory and added as it is; none: the scan was cancelled.
    func addScan(_ pages: [Data], model: AppModel) {
        // Whatever the document camera left in the app's temporary folder goes (round-9 review 5).
        TemporaryFiles.clear()
        guard !pages.isEmpty else {
            working = false
            return
        }
        message = nil
        working = true
        Task {
            defer { working = false }
            guard let pdf = model.scannedPdf(pages) else {
                message = "The scan could not be made into a PDF."
                return
            }
            await take(.data(pdf), name: "Scan \(Self.scanStamp.string(from: Date())).pdf", model: model)
        }
    }

    private static let scanStamp: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH.mm"
        return f
    }()

    private func take(_ read: FileReading.Result, name: String, model: AppModel) async {
        switch read {
        case .data(let data):
            if let refusal = model.attachmentRefusal(size: Int64(data.count)) {
                message = "“\(name)”: \(refusal)"
                return
            }
            let outcome = await model.addAttachment(name: name, data: data)
            if let text = outcome.message {
                message = "“\(name)”: \(text)"
            }
        case .tooLarge(let size):
            message = "“\(name)”: \(model.attachmentRefusal(size: size) ?? "This file is too large.")"
        case .failed:
            message = "“\(name)” could not be read."
        }
    }
}

/// The Files section of an editor: the item's files, each of which can be taken off, and the ways to add one.
struct AttachmentsEditorSection: View {
    @ObservedObject var adding: FileAdding
    @EnvironmentObject private var model: AppModel

    var body: some View {
        if let draft = model.state.attachmentDraft {
            Section {
                ForEach(draft.kept + draft.added, id: \.id) { file in
                    HStack(spacing: 8) {
                        FileRow(name: file.name, size: file.size)
                        Spacer(minLength: 8)
                        Button {
                            model.removeAttachment(file.id)
                        } label: {
                            Image(systemName: "minus.circle.fill")
                                .foregroundStyle(Palette.danger)
                                .frame(minWidth: 32, minHeight: 32)
                        }
                        .buttonStyle(.borderless)
                        .disabled(model.state.busy)
                        .accessibilityLabel("Remove \(file.name)")
                    }
                }
                if adding.working {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Adding…")
                            .foregroundStyle(Palette.inkDim)
                    }
                }
                if let upload = model.state.upload {
                    ProgressView(value: Double(upload.done), total: Double(max(upload.total, 1))) {
                        Text("Sending files: \(upload.done) of \(upload.total)")
                            .font(.footnote)
                            .foregroundStyle(Palette.inkDim)
                    }
                    .tint(Palette.gold)
                }
                Menu {
                    Button {
                        adding.choosingFiles = true
                    } label: {
                        Label("Choose a file", systemImage: "folder")
                    }
                    Button {
                        adding.choosingPhotos = true
                    } label: {
                        Label("Photo or video", systemImage: "photo.on.rectangle")
                    }
                    if VNDocumentCameraViewController.isSupported {
                        Button {
                            adding.scanning = true
                        } label: {
                            Label("Scan a document", systemImage: "doc.viewfinder")
                        }
                    }
                } label: {
                    Label("Add a file", systemImage: "paperclip")
                }
                .disabled(adding.working || model.state.busy)
                .accessibilityIdentifier("editor.add-file")
                if let message = adding.message {
                    Text(message)
                        .font(.footnote)
                        .foregroundStyle(Palette.danger)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } header: {
                Text("Files")
            } footer: {
                Text(footer(draft.limits))
            }
            .listRowBackground(Palette.raised)
        }
    }

    private func footer(_ limits: AttachmentLimitsView) -> String {
        let file = AttachmentRules.shared.size(bytes: limits.perFileBytes)
        let item = AttachmentRules.shared.size(bytes: limits.perItemBytes)
        return "Up to \(file) a file and \(item) an item. Files are encrypted on this iPhone and go up with the item when you save. A photo is copied in; the original stays in Photos."
    }
}

/// The pickers of an editor's Files section, on the editor itself so a row scrolled away cannot take them down.
struct FilePickers: ViewModifier {
    @ObservedObject var adding: FileAdding
    let model: AppModel

    func body(content: Content) -> some View {
        content
            .fileImporter(isPresented: $adding.choosingFiles, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
                adding.addFiles(result, model: model)
            }
            .photosPicker(
                isPresented: $adding.choosingPhotos,
                selection: $adding.photoItems,
                maxSelectionCount: 10,
                matching: .any(of: [.images, .videos]),
                preferredItemEncoding: .current
            )
            .onChange(of: adding.photoItems) { _, items in
                adding.addPhotos(items, model: model)
            }
            // A sheet, never a full-screen cover: a cover takes the editor off screen, and the editor's form must stay as
            // it is while the scan is made (round-9 review 4).
            .sheet(isPresented: $adding.scanning) {
                DocumentScanner(
                    preparing: {
                        adding.scanning = false
                        adding.preparingScan()
                    },
                    finished: { pages in
                        adding.scanning = false
                        adding.addScan(pages, model: model)
                    }
                )
                .ignoresSafeArea()
                .interactiveDismissDisabled()
                .privacyShield()
            }
    }
}

// MARK: - Reading what is added

/// The most a picked photo or video may be read to: set before it is loaded, read where the transfer runs.
enum ReadLimit {
    private static let lock = NSLock()
    private static var value: Int64 = 0

    static var current: Int64 {
        get {
            lock.lock()
            defer { lock.unlock() }
            return value
        }
        set {
            lock.lock()
            value = newValue
            lock.unlock()
        }
    }
}

enum FileReading {
    enum Result {
        case data(Data)
        /// Larger than it may be read to (its size, or at least this).
        case tooLarge(Int64)
        case failed
    }

    /// What the file system says the file's size is, when it says.
    static func size(_ url: URL) -> Int64? {
        (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init)
    }

    /// The file's bytes, read through a file coordinator (a file in iCloud is downloaded first) and never past [limit].
    static func read(_ url: URL, limit: Int64) -> Result {
        if let size = size(url), size > limit {
            return .tooLarge(size)
        }
        var result = Result.failed
        var error: NSError?
        NSFileCoordinator().coordinate(readingItemAt: url, options: .withoutChanges, error: &error) { url in
            guard let handle = try? FileHandle(forReadingFrom: url) else { return }
            defer { try? handle.close() }
            var data = Data()
            while Int64(data.count) <= limit {
                guard let chunk = try? handle.read(upToCount: 1 << 20), !chunk.isEmpty else { break }
                data.append(chunk)
            }
            result = Int64(data.count) > limit ? .tooLarge(Int64(data.count)) : .data(data)
        }
        return result
    }
}

/// A photo or video from the picker, as the original file: sized before it is read, never read past [ReadLimit].
struct PickedMedia: Transferable {
    let name: String
    let read: FileReading.Result

    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(importedContentType: .item) { received in
            PickedMedia(name: received.file.lastPathComponent, read: FileReading.read(received.file, limit: ReadLimit.current))
        }
    }
}

// MARK: - Scanning

/// The system's document camera. Its pages are kept as JPEG, at most [ScanPages.longSide] pixels on the long side, made
/// one at a time so only one full-size page is held at once.
struct DocumentScanner: UIViewControllerRepresentable {
    /// The scan is done and its pages are being made ready.
    let preparing: () -> Void
    /// The pages, in order; empty when the scan was cancelled or failed.
    let finished: ([Data]) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(preparing: preparing, finished: finished)
    }

    func makeUIViewController(context: Context) -> VNDocumentCameraViewController {
        let controller = VNDocumentCameraViewController()
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ controller: VNDocumentCameraViewController, context: Context) {}

    @MainActor
    final class Coordinator: NSObject, VNDocumentCameraViewControllerDelegate {
        let preparing: () -> Void
        let finished: ([Data]) -> Void

        init(preparing: @escaping () -> Void, finished: @escaping ([Data]) -> Void) {
            self.preparing = preparing
            self.finished = finished
        }

        func documentCameraViewController(_ controller: VNDocumentCameraViewController, didFinishWith scan: VNDocumentCameraScan) {
            preparing()
            let finished = finished
            Task { @MainActor in
                var pages: [Data] = []
                for index in 0..<scan.pageCount {
                    if let page = autoreleasepool(invoking: { ScanPages.jpeg(scan.imageOfPage(at: index)) }) {
                        pages.append(page)
                    }
                    await Task.yield()
                }
                finished(pages)
            }
        }

        func documentCameraViewControllerDidCancel(_ controller: VNDocumentCameraViewController) {
            finished([])
        }

        func documentCameraViewController(_ controller: VNDocumentCameraViewController, didFailWithError error: Error) {
            finished([])
        }
    }
}

enum ScanPages {
    /// 2200 pixels on the long side: a letter page at 200 dots per inch.
    static let longSide: CGFloat = 2200

    static func jpeg(_ image: UIImage) -> Data? {
        let pixels = CGSize(width: image.size.width * image.scale, height: image.size.height * image.scale)
        guard pixels.width > 0, pixels.height > 0 else { return nil }
        let factor = min(1, longSide / max(pixels.width, pixels.height))
        let target = CGSize(width: (pixels.width * factor).rounded(), height: (pixels.height * factor).rounded())
        let format = UIGraphicsImageRendererFormat()
        format.scale = 1
        format.opaque = true
        format.preferredRange = .standard
        let page = UIGraphicsImageRenderer(size: target, format: format).image { _ in
            image.draw(in: CGRect(origin: .zero, size: target))
        }
        return page.jpegData(compressionQuality: 0.7)
    }
}
