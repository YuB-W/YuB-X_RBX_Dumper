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
#include <filesystem>
#include <cstdio>
#include <array>
#include <optional>

#pragma comment(lib, "Dbghelp.lib")

namespace YuBCore {

        typedef struct _UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING, * PUNICODE_STRING;

        typedef struct _OBJECT_ATTRIBUTES {
            ULONG           Length;
            HANDLE          RootDirectory;
            PUNICODE_STRING ObjectName;
            ULONG           Attributes;
            PVOID           SecurityDescriptor;
            PVOID           SecurityQualityOfService;
        } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

    #define InitializeObjectAttributes(p, n, a, r, s) \
        do { \
            (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
            (p)->RootDirectory = r; \
            (p)->Attributes = a; \
            (p)->ObjectName = n; \
            (p)->SecurityDescriptor = s; \
            (p)->SecurityQualityOfService = NULL; \
        } while (0)

    #define STATUS_OBJECT_TYPE_MISMATCH ((NTSTATUS)0xC0000024L)

        typedef NTSTATUS(NTAPI* PNtOpenSection)(
            PHANDLE            SectionHandle,
            ACCESS_MASK        DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes
            );



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
        return (address - baseAddress); //+0x400000
    }

    uintptr_t base(uintptr_t address) {
        if (baseAddress == 0) return 0;
        return (address + baseAddress);
    }

    uintptr_t base_re(uintptr_t address) {
        if (baseAddress == 0) return 0;
        return (address - baseAddress + 0x400000);
    }

    void* allocate_memory(HANDLE process, size_t size, DWORD protection) {
        return VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, protection);
    }

    bool free_memory(HANDLE process, void* address) {
        return VirtualFreeEx(process, address, 0, MEM_RELEASE);
    }

    bool write_memory(HANDLE process, void* address, const void* data, size_t size) {
        SIZE_T written;
        return WriteProcessMemory(process, address, data, size, &written) && written == size;
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

        //std::this_thread::sleep_for(std::chrono::seconds(4));
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


    std::string GetCurrentUserName() {
        char buffer[256];
        DWORD size = sizeof(buffer);
        if (GetUserNameA(buffer, &size)) {
            return std::string(buffer);
        }
        return "";
    }


    void LaunchRobloxGame(const std::string& placeId) {
        std::string command;

        #ifdef _WIN32
                command = "start roblox://experiences/start?placeid=" + placeId;
        #endif
        std::system(command.c_str());
    }

    void CloseRoblox() {
        std::cout << "Closing Roblox..." << std::endl;
        system("taskkill /IM RobloxPlayerBeta.exe /F");
        std::cout << "Roblox closed." << std::endl;
    }

    bool IsRobloxOpen() {
        HWND hWnd = FindWindow(NULL, "Roblox");
        return hWnd != NULL;
    }

    void WaitForRobloxWindow() {
        std::cout << "Waiting for Roblox window to open..." << std::endl;

        while (!IsRobloxOpen()) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        std::cout << "Roblox window is now open!" << std::endl;
    }

    struct CodePattern {
        uintptr_t lea = 0;
        uintptr_t callBefore = 0;
        uintptr_t callAfter = 0;
        uintptr_t mov = 0;
        uintptr_t movTarget = 0;
        uintptr_t offets = 0;
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
                //std::cout << "[*] Search attempt " << attempt << "/" << maxRetries << "...\n";
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
                                    //std::cout << "[+] Found string at: 0x" << std::hex << foundAddr << std::dec << "\n";
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
                    //std::cout << "[!] String not found. Retrying in " << retryDelayMs << "ms...\n";
                std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
            }
        }

        if (verbose) {
           // std::cout << "[-] String not found in memory after " << maxRetries << " attempts.\n";
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
    
        uintptr_t from_hex(const std::string& hexStr) {
            uintptr_t value;
            std::stringstream ss;
            ss << std::hex << hexStr;
            ss >> value;
            return value;
        }


    CodePattern findLeaCallPattern(const std::string& searchStr, uintptr_t stringAddress, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0, int mov = 0 , const std::string& info = "") {
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

                   /* log(LogColor::Yellow,
                        "[CALL " + direction + "] at raw: 0x" + to_hex(callAddr) +
                        " (" + to_hex(rebase(callAddr)) + ") -> dest: 0x" +
                        to_hex(destAddr) + " (" + to_hex(rebase(destAddr)) + ") [" + status + "]");*/

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

               // log(LogColor::Green, "[+] LEA matched at 0x" + to_hex(rebase(targetAddr)) + " > 0x" + to_hex(rebase(leaAddr)));
                
                result.lea = leaAddr;

                size_t leaOffset = leaAddr - currentAddr;

                if (info.starts_with("DecryptState_offets")) {
                    size_t count = 0;
                    for (size_t j = static_cast<size_t>(leaOffset); j >= 6; --j) {
                        if (buffer[j - 6] == 0x48 && buffer[j - 5] == 0x8D && buffer[j - 4] == 0x88) {
                            int32_t offset = *reinterpret_cast<int32_t*>(&buffer[j - 3]);
                            uintptr_t foundAddr = currentAddr + j - 6;

                          //  log(LogColor::Cyan, "[LEA] Found DecryptState_offets, [rax+" + to_hex(offset) + "] at 0x" + to_hex(rebase(foundAddr)));
                           // log(LogColor::Yellow, "[*] Offset: " + std::to_string(offset));
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

                           // log(LogColor::Cyan, "[LEA] Found GlobalState_offets, [rax+" + to_hex(offset) + "] at 0x" + to_hex(rebase(foundAddr)));
                           // log(LogColor::Yellow, "[*] Offset: " + std::to_string(offset));
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
                           // log(LogColor::Green, "[*] Found .text: 000000000" + to_hex(rebase(movAddr)));
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

                            if (skippedMov < 4) {
                                //log(LogColor::Yellow, "[!] Skipping MOV at 0x" + to_hex(rebase(movAddr)));
                                ++skippedMov;
                                continue;
                            }

                            //log(LogColor::Cyan, "[MOV] Found at 0x" + to_hex(rebase(movAddr)) +
                                //" [cs:0x" + to_hex(rebase(movTarget)) + "] = RAX");

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
                        //log(LogColor::Green, "[CALL up] at 0x" + to_hex(rebase(callAddr)) +
                           /// " ! 0x" + to_hex(rebase(result.callBefore)));
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
                       // log(LogColor::Green, "[CALL down] at 0x" + to_hex(rebase(callAddr)) +
                          //  " ! 0x" + to_hex(rebase(result.callAfter)));
                        found = true;
                        break;
                    }
                }

                found = true;
                break;
            }

            currentAddr += mbi.RegionSize;
        }

        if (!result.lea) {
           // log(LogColor::Red, "[-] No LEA or matching CALL found near 0x" + to_hex(stringAddress));
        }
        else {
           // log(LogColor::Cyan, "[+] Final Result:");
           // log(LogColor::Cyan, "    LEA   : 0x" + to_hex(result.lea));

          /*  if (result.callBefore) log(LogColor::Cyan, "    CALL ↑: 0x" + to_hex(result.callBefore));
            if (result.callAfter) log(LogColor::Cyan, "    CALL ↓: 0x" + to_hex(result.callAfter));
            if (result.mov) log(LogColor::Cyan, "    MOV   : 0x" + to_hex(result.mov));*/
        }

        return result;
    }


    uintptr_t Xrefs_scan(const std::string& searchStr, int opcode = 0, int skipCallDown = 0, int skipCallUp = 0, int mov = 0 , const std::string& info = "") {

  /*      log(LogColor::Cyan, "[*] Scanning for references to: \"" + searchStr + "\"");

        log(LogColor::Cyan, "[*] opcode : 0x" + std::to_string(opcode));
        log(LogColor::Cyan, "[*] skipCallDown: " + std::to_string(skipCallDown));
        log(LogColor::Cyan, "[*] skipCallUp : " + std::to_string(skipCallUp));
        log(LogColor::Cyan, "[*] mov : " + std::to_string(mov));
*/

        uintptr_t stringAddr = YuBCore::findStringInMemory(searchStr);
        if (!stringAddr) {
            log(LogColor::Red, "[-] Could not find string in memory.");
            return 0x0;
        }

        int attempt = 1;
        while (true) {
            //log(LogColor::Yellow, "[*] Search attempt " + std::to_string(attempt++) + "...");

            YuBCore::CodePattern pattern = YuBCore::findLeaCallPattern(searchStr, stringAddr, opcode, skipCallDown, skipCallUp, mov , info);

            if (searchStr.starts_with("Cluster") || searchStr.starts_with("cannot") || searchStr.starts_with("Maximum") && pattern.movTarget) {
                //log(LogColor::Green, "[FOUND] " + searchStr);
                //log(LogColor::Green, "         movTarget   : 0x" + to_hex(rebase(pattern.movTarget)));
                return pattern.movTarget;
            }
            else if (pattern.callAfter) {
                //log(LogColor::Green, "[FOUND] " + searchStr);
                //log(LogColor::Green, "         LEA        : 0x" + to_hex(rebase(pattern.lea)));
                //log(LogColor::Green, "         call_sub callAfter!   : 0x" + to_hex(rebase(pattern.callAfter)));

                return pattern.callAfter;
            }
            else if (pattern.callBefore) {
                //log(LogColor::Green, "[FOUND] " + searchStr);
                //log(LogColor::Green, "         LEA        : 0x" + to_hex(rebase(pattern.lea)));
                //log(LogColor::Green, "         call_sub callBefore!!   : 0x" + to_hex(rebase(pattern.callBefore)));
                return pattern.callBefore;
            }
            else if (pattern.offets) {
                //log(LogColor::Green, "[FOUND] " + searchStr);
                //log(LogColor::Green, "         offets!   : 0x" + to_hex(rebase(pattern.offets)));
                return pattern.offets;
            }
        }

        return 0x0;
    }

    void dump() {
        
        log(LogColor::Green, "[!] YuB-X Dumper!");

        LaunchRobloxGame("17574618959");

        WaitForRobloxWindow();

        DWORD pid = YuBCore::GetProcessIdByName(L"RobloxPlayerBeta.exe");

        if (!pid || !YuBCore::attach(pid, "RobloxPlayerBeta.exe"));

        log(LogColor::Green, "[!] Start Dump...");

        const uintptr_t Print = Xrefs_scan("Current identity is %d", 0x48, 1, 0);
        const uintptr_t Task__Defer = Xrefs_scan("Maximum re-entrancy depth (%i) exceeded calling task.defer", 0x48, 0, 0, 0); // mov
        const uintptr_t RawScheduler = Xrefs_scan("ClusterPacketCacheTaskQueue", 0x48, 0, 0, 1); // mov
        const uintptr_t LuaVM__Load = Xrefs_scan("oldResult, moduleRef", 0x48, 8);
        const uintptr_t GetGlobalStateForInstance = Xrefs_scan("Script Start", 0x4C, 0, 2);
        const uintptr_t DecryptState = Xrefs_scan("Script Start", 0x4C, 0, 1);

        const uintptr_t DecryptState_offets = Xrefs_scan("Script Start", 0x4C, 0, 0, 0, "DecryptState_offets");
        const uintptr_t GlobalState_offets = Xrefs_scan("Script Start", 0x4C, 0, 0, 0, "GlobalState_offets");

        std::stringstream report;
        report << "\n"
            << "const uintptr_t Print                     = REBASE(0x" << std::hex << to_hex(rebase(Print)) << "); // Current identity is %d\n"
            << "const uintptr_t RawScheduler              = REBASE(0x" << to_hex(rebase(RawScheduler)) << "); // ClusterPacketCacheTaskQueue\n"
            << "const uintptr_t GetGlobalStateForInstance = REBASE(0x" << to_hex(rebase(GetGlobalStateForInstance)) << ");// Script Start\n"
            << "const uintptr_t DecryptState              = REBASE(0x" << to_hex(rebase(DecryptState)) << "); // Script Start\n"
            << "const uintptr_t LuaVM__Load               = REBASE(0x" << to_hex(rebase(LuaVM__Load)) << "); // oldResult, moduleRef = ...\n"
            << "const uintptr_t Task__Defer               = REBASE(0x" << to_hex(rebase(Task__Defer)) << "); // Maximum re-entrancy depth (%i) \n\n\n\n"
            << "namespace ScriptContext {\n"
            << "    const uintptr_t GlobalState = 0x" << to_hex(GlobalState_offets) << "; \n"
            << "    const uintptr_t DecryptState = 0x" << to_hex(DecryptState_offets) << "; \n"
            << "}\n"

            << "// YUBX::Core Dumper Finished!\n";


        CloseRoblox();

        std::string line;
        while (std::getline(report, line)) {
            log(LogColor::Green, line);
        }

        std::ofstream outFile("dump_report.txt");
        if (outFile.is_open()) {
            outFile << report.str();
            outFile.close();
            log(LogColor::Cyan, "[*] Report saved to dump_report.txt");

            #ifdef _WIN32
                        system("start dump_report.txt");
            #endif
        }
        else {
            log(LogColor::Red, "[-] Failed to save report to file.");
            std::this_thread::sleep_for(std::chrono::minutes(1));
        }
    }

    bool suspend_all_threads(DWORD pid) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        THREADENTRY32 entry;
        entry.dwSize = sizeof(THREADENTRY32);

        bool success = true;
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID == pid) {
                    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
                    if (thread) {
                        if (SuspendThread(thread) == -1) {
                            success = false;
                        }
                        CloseHandle(thread);
                    }
                }
            } while (Thread32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return success;
    }

    bool resume_all_threads(DWORD pid) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        THREADENTRY32 entry;
        entry.dwSize = sizeof(THREADENTRY32);

        bool success = true;
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID == pid) {
                    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
                    if (thread) {
                        if (ResumeThread(thread) == -1) {
                            success = false;
                        }
                        CloseHandle(thread);
                    }
                }
            } while (Thread32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return success;
    }


    void whitelist_thread(
        HANDLE process,
        HANDLE thread_handle,
        DWORD thread_id,
        uintptr_t start_address,
        uintptr_t thread_map_address)
    {
        uintptr_t map[2];
        if (!ReadProcessMemory(process, (LPCVOID)thread_map_address, &map, sizeof(map), NULL)) {
            printf("[-] Failed to read thread map\n");
            return;
        }

        FILETIME creation_time{ }, exit_time{ }, kernel_time{ }, user_time{ };
        if (!GetThreadTimes(thread_handle, &creation_time, &exit_time, &kernel_time, &user_time)) {
            printf("[-] Failed to get thread times\n");
            return;
        }

        const uint64_t creation_time_64 = (static_cast<uint64_t>(creation_time.dwHighDateTime) << 32) | creation_time.dwLowDateTime;

        uintptr_t root_entry[3];
        if (!ReadProcessMemory(process, (LPCVOID)map[0], &root_entry, sizeof(root_entry), NULL)) {
            printf("[-] Failed to read root entry\n");
            return;
        }

        std::array<uintptr_t, 7> entry{
            map[0], root_entry[1], map[0], 0, thread_id, creation_time_64, start_address
        };

        void* map_entry = allocate_memory(process, 0x38, PAGE_READWRITE);
        if (!map_entry) {
            printf("[-] Failed to allocate memory for map entry\n");
            return;
        }

        if (!write_memory(process, map_entry, entry.data(), entry.size() * sizeof(uintptr_t))) {
            printf("[-] Failed to write map entry\n");
            free_memory(process, map_entry);
            return;
        }

        uintptr_t new_map_size = map[1] + 1;
        if (!write_memory(process, (void*)(thread_map_address + 8), &new_map_size, sizeof(new_map_size))) {
            printf("[-] Failed to update map size\n");
            free_memory(process, map_entry);
            return;
        }

        std::array<uintptr_t, 3> next_entry_array{
            (uintptr_t)map_entry,
            (uintptr_t)map_entry,
            (uintptr_t)map_entry
        };

        if (!write_memory(process, (void*)root_entry[1], next_entry_array.data(), next_entry_array.size() * sizeof(uintptr_t))) {
            printf("[-] Failed to update next entry\n");
            free_memory(process, map_entry);
            return;
        }

        printf("[+] Whitelisted thread (TID: %lu)\n", thread_id);
    }

    std::optional<uintptr_t> get_function_address(const char* module_name, const char* function_name) {
        HMODULE module = LoadLibraryA(module_name);
        if (!module) {
            printf("[-] Failed to load module %s locally\n", module_name);
            return std::nullopt;
        }

        uintptr_t address = (uintptr_t)GetProcAddress(module, function_name);
        FreeLibrary(module);

        if (!address) {
            printf("[-] Failed to get address of %s in %s\n", function_name, module_name);
            return std::nullopt;
        }

        return address;
    }

    std::optional<HMODULE> get_module_base(HANDLE process, const char* module_name) {
        HMODULE modules[1024];
        DWORD needed;

        if (EnumProcessModules(process, modules, sizeof(modules), &needed)) {
            for (DWORD i = 0; i < (needed / sizeof(HMODULE)); i++) {
                char name[MAX_PATH];
                if (GetModuleBaseNameA(process, modules[i], name, sizeof(name))) {
                    if (strcmp(name, module_name) == 0) {
                        return modules[i];
                    }
                }
            }
        }
        return std::nullopt;
    }

    std::optional<HANDLE> open_process(DWORD pid) {
        HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        return handle ? std::optional<HANDLE>(handle) : std::nullopt;
    }

    int msgbox(const std::string& caption, const std::string& text) {
        try {

            log(LogColor::Green, "[!] YuB-X msgbox!");

            DWORD pid = YuBCore::GetProcessIdByName(L"RobloxPlayerBeta.exe");

            auto process = open_process(pid);
            if (!process) {
                printf("[-] Failed to open process (Error: %lu)\n", GetLastError());
                return 1;
            }

            log(LogColor::Green, "[!] Start Bypass...");

            auto local_msgbox_addr = get_function_address("user32.dll", "MessageBoxIndirectA");
            if (!local_msgbox_addr) {
                return 1;
            }

            void* data_allocation = allocate_memory(*process, 0x1000, PAGE_READWRITE);
            if (!data_allocation) {
                printf("[-] Failed to allocate memory for strings\n");
                return 1;
            }
   
            if (!write_memory(*process, data_allocation, text.c_str(), strlen(text.c_str()) + 1) ||
                !write_memory(*process, (char*)data_allocation + 0x100, caption.c_str(), strlen(caption.c_str()) + 1)) {
                printf("[-] Failed to write strings\n");
                free_memory(*process, data_allocation);
                return 1;
            }

            MSGBOXPARAMSA msgboxParams = {
                .cbSize = sizeof(MSGBOXPARAMSA),
                .hwndOwner = NULL,
                .hInstance = NULL,
                .lpszText = (LPCSTR)data_allocation,
                .lpszCaption = (LPCSTR)((char*)data_allocation + 0x100),
                .dwStyle = MB_OK | MB_ICONINFORMATION,
                .lpszIcon = NULL,
                .dwContextHelpId = 0,
                .lpfnMsgBoxCallback = NULL,
                .dwLanguageId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
            };

            auto main_module = get_module_base(*process, "RobloxPlayerBeta.exe");
            if (main_module) {
                msgboxParams.hInstance = (HINSTANCE)*main_module;
            }

            void* params_allocation = allocate_memory(*process, sizeof(MSGBOXPARAMSA), PAGE_READWRITE);
            if (!params_allocation) {
                printf("[-] Failed to allocate memory for params\n");
                free_memory(*process, data_allocation);
                return 1;
            }

            if (!write_memory(*process, params_allocation, &msgboxParams, sizeof(msgboxParams))) {
                printf("[-] Failed to write params\n");
                free_memory(*process, data_allocation);
                free_memory(*process, params_allocation);
                return 1;
            }

            printf("[+] Allocated %zu bytes at 0x%p\n", sizeof(MSGBOXPARAMSA), params_allocation);

            if (!suspend_all_threads(pid)) {
                printf("[-] Failed to suspend threads\n");
                free_memory(*process, data_allocation);
                free_memory(*process, params_allocation);
                return 1;
            }

            DWORD thread_id = 0;
            HANDLE thread = CreateRemoteThreadEx(
                *process,
                NULL,
                0,
                (LPTHREAD_START_ROUTINE)*local_msgbox_addr,
                params_allocation,
                CREATE_SUSPENDED,
                NULL,
                &thread_id
            );

            if (!thread) {
                printf("[-] Failed to create remote thread\n");
                resume_all_threads(pid);
                free_memory(*process, data_allocation);
                free_memory(*process, params_allocation);
                return 1;
            }

            printf("[+] Created thread (TID: %lu, Handle: 0x%p)\n", thread_id, thread);

            auto roblox_dll = get_module_base(*process, "RobloxPlayerBeta.dll");
            if (!roblox_dll) {
                printf("[-] Failed to get RobloxPlayerBeta.dll base address\n");
                CloseHandle(thread);
                resume_all_threads(pid);
                free_memory(*process, data_allocation);
                free_memory(*process, params_allocation);
                return 1;
            }

            whitelist_thread(
                *process,
                thread,
                thread_id,
                *local_msgbox_addr,
                (uintptr_t)*roblox_dll + 0x2c0058
            );

            if (!resume_all_threads(pid)) {
                printf("[-] Failed to resume threads\n");
                CloseHandle(thread);
                free_memory(*process, data_allocation);
                free_memory(*process, params_allocation);
                return 1;
            }

            if (ResumeThread(thread) == -1) {
                printf("[-] Failed to resume thread\n");
                CloseHandle(thread);
                free_memory(*process, data_allocation);
                free_memory(*process, params_allocation);
                return 1;
            }

            WaitForSingleObject(thread, INFINITE);

            DWORD exit_code = 0;
            if (!GetExitCodeThread(thread, &exit_code)) {
                printf("[-] Failed to get exit code\n");
            }
            else {
                printf("[+] Thread exited with code: 0x%08X\n", exit_code);
            }


            CloseHandle(thread);
            free_memory(*process, data_allocation);
            free_memory(*process, params_allocation);
        }
        catch (...) {
            printf("[-] An unknown error occurred\n");
            return 1;
        }

        return 0;
    }
}
