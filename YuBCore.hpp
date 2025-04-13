#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <DbgHelp.h>
#include <fstream>  

#pragma comment(lib, "Dbghelp.lib")

namespace YuBCore {

    enum class XrefType {
        ANY, CODE, DATA
    };

    struct CallInstruction {
        uintptr_t address;
        uintptr_t target;
        size_t size;
    };

    HANDLE hProcess = nullptr;
    uintptr_t baseAddress = 0;
    SIZE_T baseSize = 0;
    std::mutex memoryMutex;

    uintptr_t rebase(uintptr_t address) {
        if (baseAddress == 0) return 0;
        return (address - baseAddress) ; //+0x400000
    }

    uintptr_t base(uintptr_t address) {
        if (baseAddress == 0) return 0;
        return (address + baseAddress);
    }

    uintptr_t base_re(uintptr_t address) {
        if (baseAddress == 0) return 0;
        return (address - baseAddress + 0x400000);
    }

    DWORD GetProcessIdByName(const std::wstring& name) {
        PROCESSENTRY32W entry = { 0 };
        entry.dwSize = sizeof(entry);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return 0;
    }

#define MAX_SYM_NAME 256

    std::wstring GetSymbolFromAddress(HANDLE hProcess, DWORD64 addr) {
        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
        SYMBOL_INFO* sym = (SYMBOL_INFO*)buffer;
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (SymFromAddr(hProcess, addr, &displacement, sym)) {
            wchar_t wbuf[512];
            swprintf(wbuf, 512, L"%S+0x%llx", sym->Name, displacement);
            return wbuf;
        }
        return L"(unknown)";
    }

    bool SymbolStartsWith(const std::wstring& symbol, const std::wstring& prefix) {
        return symbol.substr(0, prefix.size()) == prefix;
    }

    void SuspendThreads(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            std::wcerr << L"Failed to open process.\n";
            return;
        }

        if (!SymInitialize(hProcess, "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols", TRUE)) {
            std::wcerr << L"Symbol initialization failed.\n";
            CloseHandle(hProcess);
            return;
        }

        THREADENTRY32 te{ sizeof(te) };
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            SymCleanup(hProcess);
            CloseHandle(hProcess);
            return;
        }

        bool newThreadsFound = false;
        if (Thread32First(snapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                    if (hThread) {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_CONTROL;

                        if (GetThreadContext(hThread, &ctx)) {
                            DWORD64 ip =
#ifdef _WIN64
                                ctx.Rip;
#else
                                ctx.Eip;
#endif
                            //std::wstring symbol = GetSymbolFromAddress(hProcess, ip);
                            //std::wcout << te.th32ThreadID << L", , , ntdll.dll!" << symbol << L", Normal\n";
                            SuspendThread(hThread);
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(snapshot, &te));
        }

        if (!newThreadsFound) {
            std::wcout << L"No new threads matching the pattern were found.\n";
        }

        SymCleanup(hProcess);
        CloseHandle(hProcess);
        CloseHandle(snapshot);
    }

    bool attach(DWORD pid, const std::string& moduleName) {
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
                            std::cout << "[+] Attached to module: " << szModName << "\n";
                            std::cout << "[+] Base: 0x" << std::hex << baseAddress << ", Size: 0x"
                                << baseSize << std::dec << "\n";
                            return true;
                        }
                    }
                }
            }
        }
        std::cerr << "[-] Module not found: " << moduleName << "\n";
        return false;
    }

    struct CodePattern {
        uintptr_t lea = 0;
        uintptr_t callBefore = 0;
        uintptr_t callAfter = 0;
        uintptr_t mov = 0;
        uintptr_t movTarget = 0;
    };


    uintptr_t findStringInMemory(const std::string& searchStr, bool caseInsensitive = false, bool verbose = false, int maxRetries = 5, int retryDelayMs = 500) {
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

        for (int attempt = 1; attempt <= maxRetries; ++attempt) {
            uintptr_t scanStart = baseAddress;
            MEMORY_BASIC_INFORMATION mbi = { 0 };

            if (verbose) {
                std::cout << "[*] Search attempt " << attempt << "/" << maxRetries << "...\n";
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
                                if (verbose) {
                                    std::cout << "[+] Found string at: 0x" << std::hex << foundAddr << std::dec << "\n";
                                }
                                return foundAddr;
                            }
                        }
                    }
                }
                scanStart += mbi.RegionSize;
            }

            if (attempt < maxRetries) {
                if (verbose)
                    std::cout << "[!] String not found. Retrying in " << retryDelayMs << "ms...\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
            }
        }

        if (verbose) {
            std::cout << "[-] String not found in memory after " << maxRetries << " attempts.\n";
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

    enum class LogColor {
        Default = 7,
        Green = 10,
        Yellow = 14,
        Red = 12,
        Cyan = 11
    };

    void setColor(LogColor color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<WORD>(color));
    }

    void log(LogColor color, const std::string& message, const std::string& logfile = "dump_report.log") {
        auto now = std::chrono::system_clock::now();
        auto timeT = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&timeT);

        std::ostringstream oss;
        oss << "[" << std::put_time(&tm, "%H:%M:%S") << "] " << message;

        setColor(color);
        std::cout << oss.str() << std::endl;
        setColor(LogColor::Default);

        std::ofstream logFile(logfile, std::ios_base::app);
        if (logFile.is_open()) {
            logFile << oss.str() << std::endl;
            logFile.close();
        }
        else {
            std::cerr << "Error opening log file!" << std::endl;
        }
    }


    std::string to_hex(uintptr_t addr) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << addr;
        return ss.str();
    }


    CodePattern findLeaCallPattern(const std::string& searchStr, uintptr_t stringAddress, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0, int scanMode = 1, int movvv = 0, bool mov = false) {
        CodePattern result;
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t currentAddr = baseAddress;
        size_t callScanRange = (scanMode == 2) ? 0x350 : (scanMode == 3) ? 0x550 : 0x100;

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

        log(LogColor::Cyan, "[*] Smart Scan Mode: " + std::to_string(scanMode));
        log(LogColor::Cyan, "[*] Target Address : 0x" + to_hex(rebase(stringAddress)));

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

                log(LogColor::Green, "[+] LEA matched at 0x" + to_hex(leaAddr) + " → 0x" + to_hex(targetAddr));
                result.lea = leaAddr;

                //if (mov == true) { 
                size_t skippedMov = 0;
              
                if (searchStr == "cannot %s non-suspended coroutine with arguments")
                {
                    //for (size_t i = 0; i + 6 < bytesRead; ++i) {
                    //    // Look for instruction: mov rax, qword ptr [rip + offset]
                    //    if (buffer[i] == 0x48 && buffer[i + 1] == 0x89 && buffer[i + 2] == 0x05) {
                    //        uintptr_t movInstrAddr = currentAddr + i;

                    //        // Ensure we have enough bytes to read displacement safely
                    //        int32_t relDisplacement = getRel32(buffer, i + 3);
                    //        uintptr_t resolvedTargetAddr = movInstrAddr + relDisplacement;

                    //        // Check if it points to the string we're looking for
                    //        if (resolvedTargetAddr != stringAddress) {
                    //            log(LogColor::Yellow, "[!] Skipping unrelated MOV at 0x" + to_hex(rebase(movInstrAddr)) +
                    //                " → 0x" + to_hex(rebase(resolvedTargetAddr)));
                    //            continue;
                    //        }

                    //        log(LogColor::Cyan, "[✓] MATCHED MOV at 0x" + to_hex(rebase(movInstrAddr)) +
                    //            " → [0x" + to_hex(rebase(resolvedTargetAddr)) + "]");
                    //        result.mov = movInstrAddr;
                    //        result.movTarget = resolvedTargetAddr;
                    //        break; // Stop at first valid match
                    //    }
                    //}
                }


                else {
                    for (size_t i = 0; i + 6 < bytesRead; ++i) {
                        if (buffer[i] == 0x48 && buffer[i + 1] == 0x89 && buffer[i + 2] == 0x05) {
                            uintptr_t movAddr = currentAddr + i;
                            int32_t displacement = getRel32(buffer, i + 3);
                            uintptr_t targetAddr = movAddr + 7 + displacement;
                            if (skippedMov < static_cast<size_t>(3)) {
                                log(LogColor::Yellow, "[!] Skipping MOV at 0x" + to_hex(rebase(movAddr)));
                                ++skippedMov;
                                continue;
                            }
                            log(LogColor::Cyan, "[MOV] Found at 0x" + to_hex(rebase(movAddr)) +
                                " [cs:0x" + to_hex(rebase(targetAddr)) + "] = RAX");
                            result.mov = movAddr;
                            result.movTarget = targetAddr;
                            break;
                        }
                    }
                }

                size_t callOffsetDown = findNearbyCall(buffer, i + 7, callScanRange, true, skipCallDown);
                if (callOffsetDown) {
                    uintptr_t callAddr = currentAddr + callOffsetDown;
                    int32_t rel = getRel32(buffer, callOffsetDown + 1);
                    result.callAfter = callAddr + 5 + rel;
                    log(LogColor::Green, "[CALL ↓] at 0x" + to_hex(callAddr) + " → 0x" + to_hex(result.callAfter));
                }

                size_t callOffsetUp = findNearbyCall(buffer, i, callScanRange, false, skipCallUp);
                if (callOffsetUp) {
                    uintptr_t callAddr = currentAddr + callOffsetUp;
                    int32_t rel = getRel32(buffer, callOffsetUp + 1);
                    result.callBefore = callAddr + 5 + rel;
                    log(LogColor::Green, "[CALL ↑] at 0x" + to_hex(callAddr) + " → 0x" + to_hex(result.callBefore));
                }

                found = true;
                break;  // LEA found, exit inner loop
            }

            currentAddr += mbi.RegionSize;
        }

        if (!result.lea) {
            log(LogColor::Red, "[-] No LEA or matching CALL found near 0x" + to_hex(stringAddress));
        }
        else {
            log(LogColor::Cyan, "[+] Final Result:");
            if (result.callBefore) log(LogColor::Cyan, "    CALL ↑: 0x" + to_hex(result.callBefore));
            log(LogColor::Cyan, "    LEA   : 0x" + to_hex(result.lea));
            if (result.callAfter) log(LogColor::Cyan, "    CALL ↓: 0x" + to_hex(result.callAfter));
            if (result.mov) log(LogColor::Cyan, "    MOV   : 0x" + to_hex(result.mov));
        }

        return result;
    }


    uintptr_t Xrefs_scan(const std::string& searchStr, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0, int movvv = 0, bool mov = false) {

        log(LogColor::Cyan, "[*] Scanning for references to: \"" + searchStr + "\"");

        uintptr_t stringAddr = YuBCore::findStringInMemory(searchStr);
        if (!stringAddr) {
            log(LogColor::Red, "[-] Could not find string in memory.");
            return 0x0;
        }

        int attempt = 1;
        while (true) {
            log(LogColor::Yellow, "[*] Search attempt " + std::to_string(attempt++) + "...");

            YuBCore::CodePattern pattern = YuBCore::findLeaCallPattern(searchStr,stringAddr, opcode, skipCallDown, skipCallUp, movvv, mov);

            if (searchStr == "ClusterPacketCacheTaskQueue" && searchStr == "cannot %s non-suspended coroutine with arguments" && pattern.movTarget) {
                log(LogColor::Green, "[FOUND] " + searchStr);
                log(LogColor::Green, "         movTarget   : 0x" + to_hex(rebase(pattern.movTarget)));
                return pattern.movTarget;
            }
            else if (pattern.lea) {
                log(LogColor::Green, "[FOUND] " + searchStr);
                log(LogColor::Green, "         LEA        : 0x" + to_hex(rebase(pattern.lea)));
                log(LogColor::Green, "         call_sub   : 0x" + to_hex(rebase(pattern.callAfter)));
                return pattern.callAfter;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        return 0x0;
    }

}
