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
        return (address - baseAddress) + 0x400000;
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
        uintptr_t callBefore = 0;
        uintptr_t lea = 0;
        uintptr_t callAfter = 0;
    };


    uintptr_t findStringInMemory(const std::string& searchStr, bool caseInsensitive = false, bool verbose = true) {
        std::lock_guard<std::mutex> lock(memoryMutex);
        uintptr_t scanStart = baseAddress;
        MEMORY_BASIC_INFORMATION mbi = { 0 };

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
                                //std::cout << "[+] Found string at: Rebase 0x" << std::hex << rebase(foundAddr) << "\n";
                               // std::cout << "[+] Found string at: 0x" << std::hex << foundAddr << "\n";
                            }
                            return foundAddr;
                        }
                    }
                }
            }

            scanStart += mbi.RegionSize;
        }

        if (verbose) {
            std::cout << "[-] String not found in memory.\n";
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

    void log(LogColor color, const std::string& message) {
        auto now = std::chrono::system_clock::now();
        auto timeT = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&timeT);

        std::ostringstream oss;
        oss << "[" << std::put_time(&tm, "%H:%M:%S") << "] " << message;

        setColor(color);
        std::cout << oss.str() << std::endl;
        setColor(LogColor::Default);
    }

    std::string to_hex(uintptr_t addr) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << addr;
        return ss.str();
    }


    CodePattern findLeaCallPattern(uintptr_t stringAddress, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0) {
        CodePattern result;
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t currentAddr = baseAddress;

        while (currentAddr < baseAddress + baseSize) {
            if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi)))
                break;

            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                std::vector<BYTE> buffer(mbi.RegionSize);
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {

                    auto getRel32 = [&](size_t offset) -> int32_t {
                        return *reinterpret_cast<int32_t*>(&buffer[offset]);
                        };

                    auto findCallAfter = [&](uintptr_t base, size_t start, size_t maxOffset) -> uintptr_t {
                        for (size_t j = start; j < start + maxOffset && j + 4 < bytesRead; ++j) {
                            if (buffer[j] == 0xE8) {
                                return base + j;
                            }
                        }
                        return 0;
                        };

                    for (size_t i = 0; i + 7 < bytesRead; ++i) {
                        if (opcode != 0) {
                            if (buffer[i] != opcode) continue;
                        }
                        else {
                            if (!isLeaRip(buffer[i + 1], buffer[i + 2])) continue;
                        }

                        uintptr_t leaAddr = currentAddr + i;
                        int32_t disp = getRel32(i + 3);
                        uintptr_t target = leaAddr + 7 + disp;

                        if (target != stringAddress)
                            continue;

                        result.lea = leaAddr;

                        std::ostringstream hexBytes;
                        for (size_t j = 0; j < 7; ++j)
                            hexBytes << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i + j] << " ";
                        log(LogColor::Cyan, "[LEA] Bytes at 0x" + to_hex(leaAddr) + " -> " + hexBytes.str());

                        for (size_t j = i; j > 0 && j + 4 < bytesRead; --j) {
                            if (buffer[j] == 0xE8) {
                                result.callBefore = currentAddr + j;
                                break;
                            }
                        }

                        uintptr_t callAddr = findCallAfter(currentAddr, i + 7, 0x40);
                        int skipped = 0;
                        while (callAddr&& skipped < skipCallDown) {
                            callAddr = findCallAfter(currentAddr, callAddr - currentAddr + 1, 0x40);
                            skipped++;
                        }

                        if (callAddr) {
                            int32_t callDisp = getRel32(callAddr - currentAddr + 1);
                            uintptr_t callTarget = callAddr + 5 + callDisp;
                            result.callAfter = callTarget;

                            log(LogColor::Green, "[CALL ↓] @ 0x" + to_hex(rebase(callAddr)) + " -> 0x" + to_hex(rebase(callTarget)));
                        }

                        int skippedUp = 0;
                        for (int j = static_cast<int>(i); j > 4; --j) {
                            if (buffer[j] == 0xE8) {
                                uintptr_t prevCallAddr = currentAddr + j;
                                if (skippedUp < skipCallUp) {
                                    log(LogColor::Yellow, "[CALL ↑] Skipped at 0x" + to_hex(rebase(prevCallAddr)));
                                    skippedUp++;
                                    continue;
                                }

                                int32_t callDisp = getRel32(j + 1);
                                uintptr_t callTarget = prevCallAddr + 5 + callDisp;
                                result.callBefore = callTarget;

                                log(LogColor::Green, "[CALL ↑] @ 0x" + to_hex(rebase(prevCallAddr)) + " -> 0x" + to_hex(rebase(callTarget)));
                                break;
                            }
                        }
                        return result;
                    }
                }
            }
            currentAddr += mbi.RegionSize;
        }

        if (result.lea == 0) {
            log(LogColor::Red, "[-] Failed to find LEA->CALL pattern for string: 0x" + to_hex(rebase(stringAddress)));
        }
        else {
            log(LogColor::Cyan, "[+] Pattern Summary:");
            log(LogColor::Cyan, "    CALL before LEA: 0x" + to_hex(rebase(result.callBefore)));
            log(LogColor::Cyan, "    LEA address    : 0x" + to_hex(rebase(result.lea)));
            log(LogColor::Cyan, "    CALL after LEA: 0x" + to_hex(rebase(result.callAfter)));
        }

        return result;
    }

    void Xrefs_scan(const std::string& searchStr, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0) {
        log(LogColor::Cyan, "[*] Scanning for references to: \"" + searchStr + "\"");

        uintptr_t stringAddr = YuBCore::findStringInMemory(searchStr);
        YuBCore::CodePattern pattern = YuBCore::findLeaCallPattern(stringAddr, opcode, skipCallDown, skipCallUp);

        if (pattern.lea && pattern.callAfter) {
            log(LogColor::Green, "[FOUND] " + searchStr);
            log(LogColor::Green, "        LEA       : 0x" + to_hex(rebase(pattern.lea)));
            log(LogColor::Green, "        call_sub  : 0x" + to_hex(rebase(pattern.callAfter)));
        }
        else {
            log(LogColor::Red, "[-] No pattern found for: " + searchStr);
        }
    }
}

