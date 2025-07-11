#include "Globals.hpp"
#include <map>
#include <unordered_map>

namespace YuBCore {
    struct CodePattern {
        uintptr_t lea = 0;
        uintptr_t callBefore = 0;
        uintptr_t callAfter = 0;
        uintptr_t mov = 0;
        uintptr_t movTarget = 0;
        uintptr_t offets = 0;
        uintptr_t leaTarget = 0;
    };

    uintptr_t findStringInMemory(const std::string& searchStr, bool caseInsensitive = false, bool verbose = false, int retryDelayMs = 1000, int maxRetries = -1) {
        std::lock_guard<std::mutex> lock(memoryMutex);

        const auto startTime = std::chrono::high_resolution_clock::now();
        int attempt = 1;

        std::vector<char> searchPattern(searchStr.begin(), searchStr.end());

        if (caseInsensitive) {
            std::transform(searchPattern.begin(), searchPattern.end(), searchPattern.begin(), ::tolower);
        }

        while (maxRetries < 0 || attempt <= maxRetries) {
            uintptr_t scanStart = baseAddress;
            MEMORY_BASIC_INFORMATION mbi{};

            if (verbose)
                std::cout << "\033[36m[*] Attempt " << attempt << "...\033[0m\n";

            while (scanStart < baseAddress + baseSize) {
                if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(scanStart), &mbi, sizeof(mbi)))
                    break;

                const bool readable = mbi.State == MEM_COMMIT &&
                    !(mbi.Protect & PAGE_GUARD) &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));

                if (readable) {
                    std::vector<BYTE> buffer(mbi.RegionSize);
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                        auto haystackBegin = buffer.begin();
                        auto haystackEnd = buffer.begin() + bytesRead;

                        if (caseInsensitive) {
                            std::transform(haystackBegin, haystackEnd, haystackBegin, ::tolower);
                        }

                        auto it = std::search(
                            haystackBegin, haystackEnd,
                            searchPattern.begin(), searchPattern.end()
                        );

                        if (it != haystackEnd) {
                            uintptr_t foundAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + std::distance(haystackBegin, it);

                            auto endTime = std::chrono::high_resolution_clock::now();
                            double elapsedSec = std::chrono::duration<double>(endTime - startTime).count();

                            if (verbose) {
                                std::cout << "\033[32m[+] String found at: 0x" << std::hex << foundAddr << "\033[0m\n";
                                std::cout << "\033[36m[*] Completed in " << elapsedSec << "s after " << attempt << " attempt(s)\033[0m\n";
                            }

                            return foundAddr;
                        }
                    }
                }

                scanStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            }

            if (verbose) {
                std::cout << "\033[33m[!] String not found. Retrying in " << retryDelayMs << "ms...\033[0m\n";
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
            ++attempt;
        }

        if (verbose) {
            std::cout << "\033[31m[-] Search failed after max retries.\033[0m\n";
        }

        return 0;
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
        size_t callScanRange = 0x300;

        auto getRel32 = [](const std::vector<BYTE>& buf, size_t offset) -> int32_t {
            return *reinterpret_cast<const int32_t*>(&buf[offset]);
            };

        auto findNearbyCall = [&](const std::vector<BYTE>& buf, size_t startOffset, size_t range, bool forward = true, int skip = 0) -> uintptr_t {
            size_t index = startOffset, checked = 0, skipped = 0;
            while ((forward ? index < buf.size() - 5 : index >= 5) && checked < range) {
                if (buf[index] == 0xE8) {
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

        while (currentAddr < baseAddress + baseSize) {
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


                if (info.starts_with("FFlag")) {
                    size_t functionStart = leaOffset;
                    while (functionStart > 5 && !(buffer[functionStart] == 0x48 && buffer[functionStart + 1] == 0x83 && buffer[functionStart + 2] == 0xEC)) {
                        functionStart--;
                    }

                    for (size_t j = functionStart; j + 7 < bytesRead; ++j) {
                        if (buffer[j] == 0x48 && buffer[j + 1] == 0x8B && buffer[j + 2] == 0x0D) {
                            int32_t rel = *reinterpret_cast<int32_t*>(&buffer[j + 3]);
                            uintptr_t rip = currentAddr + j + 7;
                            uintptr_t absAddr = rip + rel;

                            result.mov = currentAddr + j;
                            result.movTarget = absAddr;

                            std::cout << "[*] MOV rcx, [rip+rel] @ 0x" << std::hex << result.mov
                                << " => target: 0x" << to_hex(rebase(result.movTarget)) << std::endl;
                        }

                        if (buffer[j] == 0x4C && buffer[j + 1] == 0x8D && buffer[j + 2] == 0x05) {
                            int32_t rel = *reinterpret_cast<int32_t*>(&buffer[j + 3]);
                            uintptr_t instrAddr = currentAddr + j;
                            uintptr_t rip = instrAddr + 7;
                            uintptr_t absAddr = rip + rel;

                            if (absAddr > baseAddress && absAddr < baseAddress + baseSize) {
                                result.leaTarget = absAddr;

                                std::cout << "[LEA] found at: 0x" << to_hex(rebase(instrAddr))
                                    << " | rel32 = 0x" << rel
                                    << " | RIP = 0x" << rip
                                    << " | target = 0x" << to_hex(rebase(absAddr)) << std::endl;
                            }
                        }

                        if (result.movTarget && result.leaTarget)
                            break;
                    }
                }

                if (info.starts_with("FlogDataBank")) {
                    size_t functionStart = leaOffset;
                    while (functionStart > 5 &&
                        !(buffer[functionStart] == 0x48 &&
                            buffer[functionStart + 1] == 0x83 &&
                            buffer[functionStart + 2] == 0xEC)) {
                        functionStart--;
                    }

                    for (size_t j = functionStart; j + 7 < bytesRead; ++j) {
                        if (buffer[j] == 0x48 && buffer[j + 1] == 0x8B && buffer[j + 2] == 0x0D) {
                            int32_t rel = *reinterpret_cast<int32_t*>(&buffer[j + 3]);
                            uintptr_t rip = currentAddr + j + 7;
                            uintptr_t absAddr = rip + rel;

                            result.mov = currentAddr + j;
                            result.movTarget = absAddr;

                            std::cout << "[MOV] rcx = 0x" << std::hex << result.mov
                                << " => target = 0x" << to_hex(rebase(result.movTarget)) << std::endl;
                        }
                        if (result.movTarget)
                            break;
                    }
                }


                if (info.starts_with("DecryptState_offets")) {
                    size_t count = 0;
                    for (size_t j = static_cast<size_t>(leaOffset); j >= 6; --j) {
                        if (buffer[j - 6] == 0x48 && buffer[j - 5] == 0x8D && buffer[j - 4] == 0x88) {
                            int32_t offset = *reinterpret_cast<int32_t*>(&buffer[j - 3]);
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
                            result.movTarget = currentAddr + j - 2;
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

                            if (skippedMov < mov) {
                                skippedMov++;
                                continue;
                            }

                            result.mov = movAddr;
                            result.movTarget = movTarget;
                            break;
                        }
                    }
                }

                if (skipCallUp > 0) {
                    size_t callOffsetUp = findNearbyCall(buffer, i, callScanRange, false, skipCallUp);
                    if (callOffsetUp) {
                        result.callBefore = currentAddr + callOffsetUp + 5 + getRel32(buffer, callOffsetUp + 1);
                        break;
                    }
                }

                if (skipCallDown > 0) {
                    size_t callOffsetDown = findNearbyCall(buffer, i + 7, callScanRange, true, skipCallDown);
                    if (callOffsetDown) {
                        result.callAfter = currentAddr + callOffsetDown + 5 + getRel32(buffer, callOffsetDown + 1);
                        break;
                    }
                }
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
            else if (pattern.leaTarget) {
                if (Globals::XrefDebug) {
                    log(LogColor::Green, "[DEBUG] Returning callAfter");
                }
                return pattern.leaTarget;
            }
            if (searchStr.starts_with("Cluster") || searchStr.starts_with("cannot") || searchStr.starts_with("Maximum") || pattern.movTarget) {
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

    uintptr_t fastfindPattern(const std::string& hexPattern, bool extractOffset = false, const std::string& OffsetType = "dword") {
        auto [pattern, mask] = hexStringToPattern(hexPattern);
        if (pattern.empty() || pattern.size() != mask.size() || pattern.size() < 1) return 0; // Handles tiny patterns

        HANDLE hProc = YuBCore::hProcess;
        if (!hProc || hProc == INVALID_HANDLE_VALUE) return 0;

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        uintptr_t min = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
        uintptr_t max = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

        MEMORY_BASIC_INFORMATION mbi;
        std::vector<char> buffer;

        while (true) {
            for (uintptr_t addr = min; addr < max; addr += mbi.RegionSize) {
                if (!VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)))
                    continue;

                if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                    continue;

                SIZE_T size = mbi.RegionSize;
                buffer.resize(size);
                SIZE_T bytesRead;

                if (!ReadProcessMemory(hProc, (LPCVOID)mbi.BaseAddress, buffer.data(), size, &bytesRead))
                    continue;

                const size_t plen = pattern.size();
                if (plen > bytesRead) continue; // Avoid scanning if pattern is larger than the read memory block

                for (size_t i = 0; i <= bytesRead - plen; ++i) {
                    bool match = true;

                    for (size_t j = 0; j < plen; ++j) {
                        if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        uintptr_t result = (uintptr_t)mbi.BaseAddress + i;

                        if (extractOffset) {
                            int32_t rel = 0;
                            uintptr_t offsetAddr = result + 3;

                            if (!ReadProcessMemory(hProc, (LPCVOID)offsetAddr, &rel, sizeof(rel), nullptr))
                                continue;

                            uintptr_t finalOffset = (OffsetType == "byte")
                                ? result + rel + 7
                                : offsetAddr + rel + sizeof(rel);

                            if (finalOffset >= min && finalOffset < max)
                                return finalOffset;
                        }
                        else {
                            return result;
                        }
                    }
                }
            }

            Sleep(1); // Prevent excessive CPU usage
        }
    }

    uintptr_t findPattern2(const std::string& hexPattern, int matchIndex = 0, bool extractOffset = false, const std::string& OffsetType = "dword") {
        auto [patternBytes, mask] = hexStringToPattern(hexPattern);
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        uintptr_t minAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
        uintptr_t maxAddress = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);
        MEMORY_BASIC_INFORMATION memInfo;
        std::vector<char> buffer;
        HANDLE hProcess = YuBCore::hProcess;

        if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
            log(LogColor::Red, "[ERROR] Invalid process handle.");
            return 0;
        }

        if (Globals::PatternDebug) {
            log(LogColor::Yellow, "[DEBUG] Scanning memory...");
        }

        int currentMatch = 0;
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
                            if (currentMatch < matchIndex) {
                                ++currentMatch;
                                continue;
                            }

                            uintptr_t instructionAddress = address + i;

                            if (Globals::PatternDebug) {
                                log(LogColor::Green, "[DEBUG] Pattern found!");
                            }

                            if (extractOffset) {
                                uintptr_t foundAddress = instructionAddress;
                                uintptr_t offsetAddress = foundAddress + 3;
                                int32_t relativeOffset;

                                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(offsetAddress), &relativeOffset, sizeof(relativeOffset), nullptr)) {
                                    size_t adjustment = 0;

                                    if (OffsetType == "dword") {
                                        adjustment = sizeof(relativeOffset);
                                    }
                                    else if (OffsetType == "byte") {
                                        uintptr_t foundAddress = address + i;
                                        uintptr_t offsetAddress = foundAddress + 3;
                                        int32_t relativeOffset;

                                        if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(offsetAddress), &relativeOffset, sizeof(relativeOffset), nullptr)) {
                                            uintptr_t targetAddress = foundAddress + relativeOffset + 7;
                                            return targetAddress;
                                        }
                                        else {
                                            if (Globals::PatternDebug) {
                                                log(LogColor::Red, "[ERROR] Failed to extract byte offset.");
                                            }
                                        }
                                    }
                                    else if (OffsetType == "unk") {
                                        adjustment = sizeof(int32_t);
                                    }

                                    uintptr_t finalAddress = offsetAddress + relativeOffset + adjustment;

                                    if (finalAddress < minAddress || finalAddress >= maxAddress) {
                                        if (Globals::PatternDebug) {
                                            log(LogColor::Red, "[ERROR] Found address is out of valid range.");
                                        }
                                        return 0;
                                    }

                                    return finalAddress;
                                }

                                if (Globals::PatternDebug) {
                                    log(LogColor::Red, "[ERROR] Failed to extract offset.");
                                }
                                return 0;
                            }

                            return instructionAddress;
                        }
                    }
                }
            }

            address += memInfo.RegionSize;
        }

        if (Globals::PatternDebug) {
            log(LogColor::Red, "[ERROR] Pattern not found.");
        }

        return 0;
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
            MODULEENTRY32W modEntry;  
            modEntry.dwSize = sizeof(modEntry);
            if (Module32FirstW(hSnap, &modEntry)) {  
                do {
                    if (!_wcsicmp(modEntry.szModule, L"RobloxPlayerBeta.dll")) {  
                        modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                        break;
                    }
                } while (Module32NextW(hSnap, &modEntry));  
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

    uintptr_t dump_bitmap() {
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
                (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                !(mbi.Protect & PAGE_GUARD)) {

                buffer.resize(mbi.RegionSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(addr), buffer.data(), mbi.RegionSize, &bytesRead)) {
                    for (size_t i = 0; i + 7 <= bytesRead; ++i) {
                        // match: 4C 8B 1D ?? ?? ?? ??
                        if (buffer[i] == 0x4C && buffer[i + 1] == 0x8B && buffer[i + 2] == 0x1D) {
                            int32_t rel = *reinterpret_cast<int32_t*>(&buffer[i + 3]);
                            uintptr_t rip = addr + i + 7;
                            uintptr_t absolute = rip + rel;

                            if (absolute >= base && absolute < end) {
                                return absolute - base;  // return REBASE-able offset
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
