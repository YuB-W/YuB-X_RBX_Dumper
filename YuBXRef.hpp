#include "Globals.hpp"
namespace YuBCore {
    struct CodePattern {
        uintptr_t lea = 0;
        uintptr_t callBefore = 0;
        uintptr_t callAfter = 0;
        uintptr_t mov = 0;
        uintptr_t movTarget = 0;
        uintptr_t offets = 0;
    };

    uintptr_t findStringInMemory(const std::string& searchStr, bool caseInsensitive = false, bool verbose = false, int retryDelayMs = 1000) {
        std::lock_guard<std::mutex> lock(memoryMutex);

        auto matches = [&searchStr, caseInsensitive](const BYTE* data, size_t len) -> bool {
            if (len < searchStr.length()) return false;
            for (size_t i = 0; i < searchStr.length(); ++i) {
                char memChar = static_cast<char>(data[i]);
                char targetChar = searchStr[i];

                if (caseInsensitive) {
                    memChar = std::tolower(memChar);
                    targetChar = std::tolower(targetChar);
                }

                if (memChar != targetChar)
                    return false;
            }
            return true;
            };

        int attempt = 1;
        auto startTime = std::chrono::high_resolution_clock::now();

        while (true) {
            uintptr_t scanStart = baseAddress;
            MEMORY_BASIC_INFORMATION mbi = { 0 };

            if (verbose) {
                std::cout << "[*] Search attempt " << attempt << "...\n";
            }

            while (scanStart < baseAddress + baseSize) {
                if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(scanStart), &mbi, sizeof(mbi)))
                    break;

                if ((mbi.State == MEM_COMMIT) &&
                    (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                    !(mbi.Protect & PAGE_GUARD)) {

                    std::vector<BYTE> buffer(mbi.RegionSize);
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                        for (size_t i = 0; i <= bytesRead - searchStr.length(); ++i) {
                            if (matches(&buffer[i], searchStr.length())) {
                                uintptr_t foundAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + i;

                                auto endTime = std::chrono::high_resolution_clock::now();
                                double elapsedSec = std::chrono::duration<double>(endTime - startTime).count();

                                if (verbose) {
                                    std::cout << "[+] Found string at: 0x" << std::hex << foundAddr << std::dec << "\n";
                                    std::cout << "[*] Search completed in " << elapsedSec << " seconds after " << attempt << " attempts.\n";
                                }

                                return foundAddr;
                            }
                        }
                    }
                }

                scanStart += mbi.RegionSize;
            }

            if (verbose) {
                std::cout << "[!] String not found. Retrying in " << retryDelayMs << "ms...\n";
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
            ++attempt;
        }

        return 0; // Technically unreachable unless interrupted
    }

    enum class OperandType {
        r16_32,
        m32
    };

    struct OpInfo {
        std::string opcode;
        std::string mnemonic;
        std::vector<OperandType> operandTypes;
        std::string description;

        OpInfo(const std::string& opc, const std::string& mnem,
            std::initializer_list<OperandType> ops, const std::string& desc)
            : opcode(opc), mnemonic(mnem), operandTypes(ops), description(desc) {
        }
    };

    bool isLeaRip(uint8_t reg1, uint8_t reg2) {
        OpInfo leaInfo("8D", "lea", { OperandType::r16_32, OperandType::m32 }, "Load Effective Address");
        return true;
    }

    CodePattern findLeaCallPattern(const std::string& searchStr, uintptr_t stringAddress, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0, int mov = 0, const std::string& info = "") {
        CodePattern result;
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t currentAddr = baseAddress;

        int scanMode = 1;

        size_t callScanRange = (scanMode == 2) ? 0x350 : (scanMode == 3) ? 0x550 : 0x100;

        auto getRel32 = [](const std::vector<BYTE>& buf, size_t offset) -> int32_t {
            return *reinterpret_cast<const int32_t*>(&buf[offset]);
            };

        auto findNearbyCall = [&](const std::vector<BYTE>& buf, size_t startOffset, size_t range, bool forward = true, int skip = 0) -> uintptr_t {
            size_t index = startOffset, checked = 0, skipped = 0;
            while ((forward ? index < buf.size() - 5 : index >= 5) && checked < range) {
                if (buf[index] == 0xE8) {
                    uintptr_t callAddr = index;
                    int32_t rel = getRel32(buf, index + 1);
                    uintptr_t destAddr = callAddr + 5 + rel;

                    // Clean formatted debug output
                    std::string direction = forward ? "down" : "up";
                    std::string status = (skipped < skip) ? "skipped" : "selected";
                    if (skipped++ < skip) {
                        index += forward ? 1 : -1;
                        ++checked;
                        continue;
                    }
                    return index;
                }
                index += forward ? 1 : -1;
                ++checked;
            }
            return 0;
            };



        bool found = false;
        while (!found && currentAddr < baseAddress + baseSize) {
            if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi))) break;
            if (!(mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))) {
                currentAddr += mbi.RegionSize;
                continue;
            }

            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;
            if (!ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                currentAddr += mbi.RegionSize;
                continue;
            }

            for (size_t i = 0; i + 7 < bytesRead; ++i) {
                if (opcode ? (buffer[i] != opcode) : (!isLeaRip(buffer[i + 1], buffer[i + 2]))) continue;

                uintptr_t leaAddr = currentAddr + i;
                int32_t displacement = getRel32(buffer, i + 3);
                uintptr_t targetAddr = leaAddr + 7 + displacement;
                if (targetAddr != stringAddress) continue;
                result.lea = leaAddr;

                size_t leaOffset = leaAddr - currentAddr;

                if (info.starts_with("DecryptState_offets")) {
                    size_t count = 0;
                    for (size_t j = static_cast<size_t>(leaOffset); j >= 6; --j) {
                        if (buffer[j - 6] == 0x48 && buffer[j - 5] == 0x8D && buffer[j - 4] == 0x88) {
                            int32_t offset = *reinterpret_cast<int32_t*>(&buffer[j - 3]);
                            uintptr_t foundAddr = currentAddr + j - 6;
                            if (count == 0) result.offets = offset;
                            count++;
                            if (count == 2) break;
                        }
                    }
                }

                if (info.starts_with("GlobalState_offets")) {
                    size_t count = 0;
                    for (size_t j = static_cast<size_t>(leaOffset); j >= 6; --j) {
                        if (buffer[j - 6] == 0x48 && buffer[j - 5] == 0x8D && buffer[j - 4] == 0x88) {
                            int32_t offset = *reinterpret_cast<int32_t*>(&buffer[j - 3]);
                            uintptr_t foundAddr = currentAddr + j - 6;
                            if (count == 1) result.offets = offset;
                            count++;
                            if (count == 2) break;
                        }
                    }
                }

                if (searchStr.starts_with("Maximum")) {

                    int skipCount = 0;

                    for (size_t j = i; j >= 2; --j) {
                        if (buffer[j - 2] == 0x48) {
                            if (skipCount < 17) {
                                ++skipCount;
                                continue;
                            }

                            uintptr_t movAddr = currentAddr + j - 2;
                            result.movTarget = movAddr;
                            break;
                        }
                    }
                }

                if (mov > 0) {
                    size_t skippedMov = 0;

                    for (size_t j = 0; j + 6 < bytesRead; ++j) {
                        if (buffer[j] == 0x48 && buffer[j + 1] == 0x89 && buffer[j + 2] == 0x05) {
                            uintptr_t movAddr = currentAddr + j;
                            int32_t disp = getRel32(buffer, j + 3);
                            uintptr_t movTarget = movAddr + 7 + disp;

                            if (skippedMov < mov && info != "mov") {
                                log(LogColor::Yellow, "\n\n[!] Skipping MOV at 0x" + to_hex(rebase(movAddr)));
                                log(LogColor::Yellow, "[!] Offset RAX at: 0x" + to_hex(rebase(movTarget)) + "\n\n");
                                ++skippedMov;
                                continue;
                            }


                            if (skippedMov < mov && info == "debug") {
                                log(LogColor::Yellow, "\n\n[!] Skipping MOV at 0x" + to_hex(rebase(movAddr)));
                                log(LogColor::Yellow, "[!] Offset RAX at: 0x" + to_hex(rebase(movTarget)) + "\n\n");
                                ++skippedMov;
                                continue;
                            }

                            log(LogColor::Cyan, "[MOV] Found at 0x" + to_hex(rebase(movAddr)) +
                                " [cs:0x" + to_hex(rebase(movTarget)) + "] = RAX");
                            log(LogColor::Cyan, "[Offset] Found at 0x" + to_hex(rebase(movTarget)) + "\n\n");

                            result.mov = movAddr;
                            result.movTarget = movTarget;
                            break;
                        }
                    }
                }

                // CALL UP
                if (skipCallUp > 0) {
                    size_t callOffsetUp = findNearbyCall(buffer, i, callScanRange, false, skipCallUp);
                    if (callOffsetUp) {
                        uintptr_t callAddr = currentAddr + callOffsetUp;
                        int32_t rel = getRel32(buffer, callOffsetUp + 1);
                        result.callBefore = callAddr + 5 + rel;
                        found = true;
                        break;
                    }
                }

                // CALL DOWN
                if (skipCallDown > 0) {
                    size_t callOffsetDown = findNearbyCall(buffer, i + 7, callScanRange, true, skipCallDown);
                    if (callOffsetDown) {
                        uintptr_t callAddr = currentAddr + callOffsetDown;
                        int32_t rel = getRel32(buffer, callOffsetDown + 1);
                        result.callAfter = callAddr + 5 + rel;
                        found = true;
                        break;
                    }
                }

                found = true;
                break;
            }

            currentAddr += mbi.RegionSize;
        }
        return result;
    }

    uintptr_t Xrefs_scan(const std::string& searchStr, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0, int mov = 0, const std::string& info = "") {
        uintptr_t stringAddr = YuBCore::findStringInMemory(searchStr);
        if (!stringAddr) {
            log(LogColor::Red, "[-] Could not find string in memory.");
            return 0x0;
        }
        int attempt = 1;
        while (true) {
            if (Globals::XrefDebug) {
                log(LogColor::Cyan, "[*] Starting Xrefs_scan for: " + searchStr);
                log(LogColor::Yellow, "[*] Attempt #" + std::to_string(attempt) + " scanning LEA call pattern...");
            }
            YuBCore::CodePattern pattern = YuBCore::findLeaCallPattern(searchStr, stringAddr, opcode, skipCallDown, skipCallUp, mov, info);
            if (Globals::XrefDebug) {
                log(LogColor::Cyan, "[DEBUG] searchStr: " + searchStr);
                log(LogColor::Cyan, "[DEBUG] stringAddr: " + std::to_string(stringAddr));
                log(LogColor::Cyan, "[DEBUG] opcode: " + std::to_string(opcode));
            }


            if (searchStr.starts_with("Cluster") || searchStr.starts_with("cannot") || searchStr.starts_with("Maximum") && pattern.movTarget) {
                if (Globals::XrefDebug) {
                    log(LogColor::Green, "[DEBUG] Returning movTarget");
                }
                return pattern.movTarget;
            }
            else if (pattern.callAfter) {
                if (Globals::XrefDebug) {
                    log(LogColor::Green, "[DEBUG] Returning callAfter");
                }
                return pattern.callAfter;
            }
            else if (pattern.callBefore) {
                if (Globals::XrefDebug) {
                    log(LogColor::Green, "[DEBUG] Returning callBefore");
                }
                return pattern.callBefore;
            }
            else if (pattern.offets) {
                if (Globals::XrefDebug) {
                    log(LogColor::Green, "[DEBUG] Returning offsets");
                }
                return pattern.offets;
            }
            if (Globals::XrefDebug) {
                log(LogColor::Red, "[DEBUG] No match found, continuing...");
            }
        }


        return 0x0;
    }

    std::pair<std::vector<char>, std::string> hexStringToPattern(const std::string& hexPattern) {
        std::vector<char> bytes;
        std::string mask;
        std::istringstream stream(hexPattern);
        std::string byteString;

        while (stream >> byteString) {
            if (byteString == "?") {
                bytes.push_back(0x00);  // Wildcard
                mask += '?';
            }
            else {
                bytes.push_back(static_cast<char>(strtol(byteString.c_str(), nullptr, 16)));
                mask += 'x';
            }
        }
        return { bytes, mask };
    }



    uintptr_t findPattern(const std::string& hexPattern, bool extractOffset = false) {
        auto [patternBytes, mask] = hexStringToPattern(hexPattern);

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        uintptr_t minAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
        uintptr_t maxAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

        MEMORY_BASIC_INFORMATION memInfo;
        std::vector<char> buffer;

        HANDLE hProcess = YuBCore::hProcess;
        if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] Invalid process handle.\n";
            return 0;
        }

        for (uintptr_t address = minAddress; address < maxAddress;) {
            if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &memInfo, sizeof(memInfo)) == 0) {
                address += 0x1000;
                continue;
            }

            if (memInfo.State == MEM_COMMIT &&
                (memInfo.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY)) &&
                !(memInfo.Protect & PAGE_GUARD)) {

                size_t regionSize = memInfo.RegionSize;
                buffer.resize(regionSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buffer.data(), regionSize, &bytesRead)) {
                    for (size_t i = 0; i <= bytesRead - patternBytes.size(); ++i) {
                        bool match = true;
                        for (size_t j = 0; j < patternBytes.size(); ++j) {
                            if (mask[j] == 'x' && buffer[i + j] != patternBytes[j]) {
                                match = false;
                                break;
                            }
                        }
                        if (match) {
                            uintptr_t foundAddress = address + i;

                            if (extractOffset) {
                                uintptr_t offsetAddress = foundAddress + 3; // Offset is typically after instruction prefix
                                int32_t relativeOffset;

                                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(offsetAddress), &relativeOffset, sizeof(relativeOffset), nullptr)) {
                                    return offsetAddress + relativeOffset + sizeof(relativeOffset);  // Fully automatic adjustment
                                }
                                std::cerr << "[!] Failed to extract offset address.\n";
                                return 0;
                            }

                            return foundAddress;  // Return pattern match address
                        }
                    }
                }
            }
            address += memInfo.RegionSize;
        }
        return 0;  // Pattern not found
    }






    bool match_with_wildcards(const uint8_t* data, const std::vector<uint8_t>& pattern) {
        for (size_t i = 0; i < pattern.size(); ++i) {
            if (pattern[i] != 0x00 && data[i] != pattern[i])
                return false;
        }
        return true;
    }

    bool attachx(DWORD pid, const std::string& moduleName) {
        std::lock_guard<std::mutex> lock(memoryMutex);
        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, pid);
        if (!hProcess) {
            std::cerr << "[-] Failed to open process. Error: " << GetLastError() << "\n";
            return false;
        }
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH] = { 0 };
                if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                    if (_stricmp(szModName, moduleName.c_str()) == 0) {
                        MODULEINFO modInfo = { 0 };
                        if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                            baseAddress = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                            baseSize = modInfo.SizeOfImage;
                           // std::cout << "[+] Attached to module: " << szModName << "\n";
                           // std::cout << "[+] Base: 0x" << std::hex << baseAddress << ", Size: 0x"
                           //     << baseSize << std::dec << "\n";
                            return true;
                        }
                    }
                }
            }
        }
        std::cerr << "[-] Module not found: " << moduleName << "\n";
        return false;
    }

    auto get_hyperion() -> uintptr_t {

        uintptr_t modBaseAddr = 0;
        DWORD pid = GetProcessIdByName(L"RobloxPlayerBeta.exe");
        if (!pid || !attachx(pid, "RobloxPlayerBeta.exe"))
            return 0x0;

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W modEntry;  // Use WIDE version
            modEntry.dwSize = sizeof(modEntry);
            if (Module32FirstW(hSnap, &modEntry)) {  // Use Module32FirstW
                do {
                    if (!_wcsicmp(modEntry.szModule, L"RobloxPlayerBeta.dll")) {  // Ensure WCHAR string
                        modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                        break;
                    }
                } while (Module32NextW(hSnap, &modEntry));  // Use Module32NextW
            }
        }
        CloseHandle(hSnap);
        return modBaseAddr;
    }

    size_t get_hyperion_size() {
        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
            return 0;

        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                if (reinterpret_cast<uintptr_t>(hMods[i]) == get_hyperion())
                    return static_cast<size_t>(modInfo.SizeOfImage);
            }
        }

        return 0;
    }



    auto dump_threadmap() -> uintptr_t {
        std::vector<std::vector<uint8_t>> patterns = {
            { 0x4C, 0x03, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x41, 0x83, 0xE2 } // Updated pattern
        };

        uintptr_t base = get_hyperion();
        SIZE_T size = get_hyperion_size();

        if (!hProcess || hProcess == INVALID_HANDLE_VALUE || !base || !size)
            return 0;

        MEMORY_BASIC_INFORMATION mbi;
        std::vector<uint8_t> buffer;
        uintptr_t end = base + size;

        for (uintptr_t addr = base; addr < end;) {
            if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
                addr += 0x1000;
                continue;
            }

            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY)) &&
                !(mbi.Protect & PAGE_GUARD)) {

                buffer.resize(mbi.RegionSize);
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), buffer.data(), mbi.RegionSize, &bytesRead)) {
                    for (auto& pat : patterns) {
                        for (size_t i = 0; i + pat.size() < bytesRead; ++i) {
                            bool match = true;

                            for (size_t j = 0; j < pat.size(); ++j) {
                                if (pat[j] != 0x00 && buffer[i + j] != pat[j]) { // Wildcard handling
                                    match = false;
                                    break;
                                }
                            }

                            if (match) {
                                int32_t rel = *reinterpret_cast<int32_t*>(&buffer[i + 3]);
                                uintptr_t abs = addr + i + 7 + rel;
                                return abs - base;
                            }
                        }
                    }
                }
            }

            addr += mbi.RegionSize;
        }

        return 0;
    }

    
    auto dump_setinsert() -> uintptr_t {
        std::vector<uint8_t> pattern = {
            0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x53,
            0x48, 0x83, 0xEC, 0x00,  // Wildcard (?)
            0x48, 0x8D, 0x6C, 0x24, 0x00,  // Wildcard (?)
            0x48, 0xC7, 0x45, 0x00, 0xFE, 0xFF, 0xFF, 0xFF,
            0x4C, 0x89, 0xC3
        };

        uintptr_t base = get_hyperion(); // Ensure this is correct!
        SIZE_T size = get_hyperion_size();

        if (!hProcess || hProcess == INVALID_HANDLE_VALUE || !base || !size)
            return 0;

        MEMORY_BASIC_INFORMATION mbi;
        std::vector<uint8_t> buffer;
        uintptr_t end = base + size;

        for (uintptr_t addr = base; addr < end;) {
            if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
                addr += 0x1000;
                continue;
            }

            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY)) &&
                !(mbi.Protect & PAGE_GUARD)) {

                buffer.resize(mbi.RegionSize);
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), buffer.data(), mbi.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i + pattern.size() <= bytesRead; ++i) {
                        bool match = true;

                        for (size_t j = 0; j < pattern.size(); ++j) {
                            if (pattern[j] != 0x00 && buffer[i + j] != pattern[j]) { // Ignore wildcards (`?`)
                                match = false;
                                break;
                            }
                        }

                        if (match) {
                            return addr + i - base; // Adjusted rebasing correction
                        }
                    }
                }
            }

            addr += mbi.RegionSize;
        }

        return 0;
    }






    














    
}