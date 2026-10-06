// SPDX-License-Identifier: MIT
// Copyright (c) 2026 dhtfish98
import Foundation
import Virtualization

@main
struct GuestVM {
    static func main() async throws {
        guard CommandLine.arguments.count == 3 else {
            fputs("usage: guest_vm KERNEL_IMAGE INITRAMFS\n", stderr)
            exit(64)
        }
        let settings = VZVirtualMachineConfiguration()
        settings.cpuCount = 2
        settings.memorySize = 1024 * 1024 * 1024
        settings.platform = VZGenericPlatformConfiguration()
        let loader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: CommandLine.arguments[1]))
        loader.initialRamdiskURL = URL(fileURLWithPath: CommandLine.arguments[2])
        loader.commandLine = "console=hvc0 rdinit=/bin/sh panic=0"
        settings.bootLoader = loader
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
        serial.attachment = VZFileHandleSerialPortAttachment(
            fileHandleForReading: FileHandle.standardInput,
            fileHandleForWriting: FileHandle.standardOutput
        )
        settings.serialPorts = [serial]
        try settings.validate()
        let machine = VZVirtualMachine(configuration: settings)
        try await machine.start()
        while machine.state != .stopped {
            try await Task.sleep(for: .milliseconds(250))
        }
    }
}
