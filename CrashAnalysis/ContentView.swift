//
//  ContentView.swift
//  CrashAnalysis
//
//  Created by mac on 2024/6/21.
//

import SwiftUI

struct ContentView: View {
    
    
    /// dSYM 文件路径
    @State private var dsymFilePath: String = ""
    
    /// Crash 文件路径
    @State private var crashFilePath: String = ""
    
    /// 解析后的内容
    @State private var parsedOutput: String = ""
    
    /// 处理中状态标识
    @State private var isProcessing: Bool = false
    
    private var testText: String = ""
    
    var body: some View {
        VStack {
            HStack {
                VStack {
                    Text("dSYM File", comment: "选择 .dSYM 文件")
                    FilePickerButton(filePath: $dsymFilePath)
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [5]))
                    .foregroundColor(.gray)
                )
                .onDrop(of: [.fileURL], isTargeted: nil, perform: { providers in
                    if let provider = providers.first {
                        provider.loadItem(forTypeIdentifier: "public.file-url", options: nil) { (urlData, error) in
                            DispatchQueue.main.async {
                                if let urlData = urlData as? Data, let url = URL(dataRepresentation: urlData, relativeTo: nil) {
                                    dsymFilePath = url.path
                                }
                            }
                            
                        }
                        return true
                    }
                    return false
                })
                VStack {
                    Text("Crash File", comment: "选择 .crash 文件，可以是 .txt")
                    FilePickerButton(filePath: $crashFilePath)
                }
                .padding()
                .background(RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [5]))
                    .foregroundColor(.gray)
                )
                .onDrop(of: [.fileURL], isTargeted: nil, perform: { providers in
                    if let provider = providers.first {
                        provider.loadItem(forTypeIdentifier: "public.file-url", options: nil) { (urlData, error) in
                            DispatchQueue.main.async {
                                if let urlData = urlData as? Data, let url = URL(dataRepresentation: urlData, relativeTo: nil) {
                                    crashFilePath = url.path
                                }
                            }
                            
                        }
                        return true
                    }
                    return false
                })
            }
            Button(action: parseCrashFile) {
                Text("Parse Crash File", comment: "解析 Crash 文件")
            }
            .padding()
            .disabled(dsymFilePath.isEmpty || crashFilePath.isEmpty)
            
            if isProcessing {
                ProgressView(
                    String(localized: "Processing...", comment: "处理中..."))
                .padding()
            }
            TextEditor(text: .constant(parsedOutput))
                .padding()
                .frame(maxWidth: .infinity,maxHeight: .infinity)
                .scrollContentBackground(.hidden)
                .background(RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [5]))
                    .foregroundColor(.gray)
                )
        }
        .padding()
    }
    
    /// 开始处理 dSYM 与 Crash 文件
    func parseCrashFile() {
        guard !dsymFilePath.isEmpty, !crashFilePath.isEmpty else {
            parsedOutput = String(localized: "Please select both dSYM and Crash files", comment: "请选择 dSYM 和 Crash 文件")
            return
        }
        
        isProcessing = true
        
        let hexAddresses = extractHexAddresses(from: crashFilePath)
        DispatchQueue.global(qos: .userInitiated).async {
            var crashContent = ""
            do {
                crashContent = try String(contentsOfFile: crashFilePath)
            } catch {
                DispatchQueue.main.async {
                    parsedOutput = String(localized: "Error read the crash file failed: \(error.localizedDescription)", comment: "读取 crash 文件失败")
                    isProcessing = false
                }
                return
            }
            
            let results = hexAddresses.map { address in
                let resolved = runAtosCommand(address: address, dsymFilePath: dsymFilePath)
                return (original: address.originalLine, resolved: resolved)
            }
            
            for result in results {
                crashContent = crashContent.replacingOccurrences(of: result.original, with: result.resolved)
            }
            
            DispatchQueue.main.async {
                parsedOutput = crashContent
                isProcessing = false
            }
        }
    }
    
    
    /// 解析 Crash 文件内容
    /// - Parameter crashFilePath: Crash 文件路径
    /// - Returns: 需要后续处理的 16 进制内容
    func extractHexAddresses(from crashFilePath: String) -> [(originalLine: String, address: String, offset: String)] {
        
        var result: [(String, String, String)] = []
        do {
            let crashContent = try String(contentsOfFile: crashFilePath)
            let regex = try NSRegularExpression(pattern: "(0x[0-9a-fA-F]+).*?(\\d+)")
            let matches = regex.matches(in: crashContent, range: NSRange(crashContent.startIndex..., in: crashContent))
            for match in matches {
                let orignalLine = String(crashContent[Range(match.range, in: crashContent)!])
                let addressRange = Range(match.range(at: 1), in: crashContent)!
                let offsetRange = Range(match.range(at: 2), in: crashContent)!
                let address = String(crashContent[addressRange])
                let offsetSting = String(crashContent[offsetRange])
                
                let offsetHex = String(format: "%lx", UInt64(offsetSting) ?? 0)
                result.append((orignalLine, address, offsetHex))
            }
        } catch {
            print("地址处理错误\(error)")
        }
        return result
    }
    
    
    /// 使用 atos 解析 Crash 16 进制内容
    /// - Parameters:
    ///   - address: Crash 16 进制地址
    ///   - dsymFilePath: 可最终执行路径
    /// - Returns: 解析的内容结果
    func runAtosCommand(address: (originalLine: String, address: String, offset: String), dsymFilePath: String) -> String {
        let process = Process()
        let pipe = Pipe()
        
        
        let dwarfFilePath = findDwarfFilePath(for: dsymFilePath)
        guard !dwarfFilePath.isEmpty else {
            return String(localized:"DWARF file not found in dSYM", comment: "没有在 dSYM 中找到 DWARF 文件")
        }
        
        
        let atosPath = findAtosPath()
        guard !atosPath.isEmpty else {
            return String(localized: "atos command not found", comment: "没有找到 atos 命令")
        }
        
        guard let originalAddress = UInt64(address.address.dropFirst(2), radix: 16), let offset = UInt64(address.offset, radix: 16) else {
            return String(localized: "Invalid address or offset", comment: "无效的地址或偏移量")
        }
        
        let baseAddress = originalAddress - offset
        let baseAddressHex = String(format: "0x%lx", baseAddress)
        let finalAddress = address.address
        
        process.executableURL = URL(fileURLWithPath: atosPath)
        process.arguments = ["-o", dsymFilePath, "-l", baseAddressHex, finalAddress]
        process.standardOutput = pipe
        
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let result = String(data: data, encoding: .utf8) ??  String(localized: "Error parsing address: \(finalAddress)", comment: "解析地址错误")
            return address.originalLine.replacingOccurrences(of: address.address, with: result.trimmingCharacters(in: .whitespacesAndNewlines))
        }catch {
            return String(localized: "Error running atos command for address: \(finalAddress)" , comment: "运行 atos 命令获取地址错误")
        }
    }
    
    /// 拼接完整的 dSYM 路径
    /// - Parameter dsymFilePath: .dSYM 所在路径
    /// - Returns: 可被 atos 执行的完整路径
    func findDwarfFilePath(for dsymFilePath: String) -> String {
        let dwarfDirectoryPath = "\(dsymFilePath)/Contents/Resources/DWARF"
        do {
            let fileManager = FileManager.default
            let contents = try fileManager.contentsOfDirectory(atPath: dwarfDirectoryPath)
            let dsymBaseName = (dsymFilePath as NSString).lastPathComponent.replacingOccurrences(of: ".app.dSYM", with: "")
            if let dwarfFile = contents.first(where: { $0 == dsymBaseName}) {
                return "\(dwarfDirectoryPath)/\(dwarfFile)"
            }
        }catch {
            print("DAWRF 路径错误：\(error)")
        }
        return ""
    }
    
    /// 查找命中对应路径中 atos
    /// - Returns: atos 路径
    func findAtosPath() -> String {
        let possiblePaths = ["/usr/bin/atos", "/usr/local/bin/atos", "/opt/homebrew/bin/atos"]
        for path in possiblePaths {
            if FileManager.default.fileExists(atPath: path) {
                return path
            }
        }
        return ""
    }
    
    
    
}

/// 文件选择器
struct FilePickerButton: View {
    
    @Binding var filePath: String
    
    /// 选择文件 Button 实现
    var body: some View {
        Button(action: selectFile, label: {
            Text(filePath.isEmpty ? String(localized: "select or drop", comment: "选择或通过鼠标拖入对应文件"): filePath).frame(maxWidth: .infinity)
        })
    }
    
    /// 选中的文件路径
    func selectFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        
        if panel.runModal() == .OK {
            filePath = panel.url?.path ?? ""
        }
    }
}


//atos -o Factory-Online.app.dSYM/Contents/Resources/DWARF/Factory-Online -l 0x102514000 0x0000000103450b5c


#Preview {
    ContentView()
}
