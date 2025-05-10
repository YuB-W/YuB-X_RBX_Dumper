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
#include <sstream>
#include "YuBUtils.hpp"
#include "YuBRoblox.hpp"
#include "YuBXRef.hpp"
#include "YuBMemory.hpp"
#include "Dumper.hpp"


#pragma comment(lib, "Dbghelp.lib")

namespace YuBCore {
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

    auto check_is_running(const std::string& process_name) -> bool {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32 pe{};
        pe.dwSize = sizeof(pe);

        std::string lower_name = process_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

        bool found = false;
        if (Process32First(snapshot, &pe)) {
            do {
                std::string current = pe.szExeFile;
                std::transform(current.begin(), current.end(), current.begin(), ::tolower);

                if (current.find(lower_name) != std::string::npos) {
                    found = true;
                    break;
                }
            } while (Process32Next(snapshot, &pe));
        }

        CloseHandle(snapshot);
        return found;
    }




#include <chrono>
#include "Patterns.hpp"

    // Function to display a progress bar and detect if it's stuck
    void showProgressBar(int completed, int total) {
        static int lastProgress = -1;
        static auto lastTime = std::chrono::steady_clock::now();
        const int barWidth = 40;
        float progress = static_cast<float>(completed) / total;
        int pos = barWidth * progress;

        std::cout << "[";
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos)
                std::cout << "=";
            else
                std::cout << " ";
        }
        std::cout << "] " << int(progress * 100.0) << "%\r";
        std::cout.flush();

        // Check if progress is stuck
        if (int(progress * 100.0) == lastProgress) {
            auto now = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - lastTime).count();

            // If stuck for more than 10 seconds, rejoin
            if (duration > 10) {
                std::cout << "\n[!] Progress stuck! Restarting...\n";
                LaunchRobloxGame("17574618959"); // Re-launch
            }
        }
        else {
            lastProgress = int(progress * 100.0);
            lastTime = std::chrono::steady_clock::now();
        }
    }


    void dump() {
        log(LogColor::Green, "[!] YuB-X Dumper!");

        if (Globals::StartGameBeforeDummp)
        {
            LaunchRobloxGame("17574618959");
        }
        WaitForRobloxProcess();

        if (check_is_running("RobloxPlayerBeta.exe")) {
            DWORD pid = YuBCore::GetProcessIdByName(L"RobloxPlayerBeta.exe");
            if (!pid || !YuBCore::attach(pid, "RobloxPlayerBeta.exe"))
                return;

            auto process = TMEM::setup(pid);
            dumper->bind(std::move(process));

            log(LogColor::Green, "[!] Start Dump...");
            std::cout << "\nProgress:\n";

            int totalScans = 18; // Including the new offsets
            int foundOffsets = 0;

            // Offset scanning while dynamically updating the progress bar
            const uintptr_t Print = Xrefs_scan("Current identity is %d", 0x48, 1, 0);
            foundOffsets += (Print != 0); showProgressBar(foundOffsets, totalScans);

            /*const uintptr_t Task__Defer = Xrefs_scan("Maximum re-entrancy depth (%i) exceeded calling task.defer", 0x48, 0, 0, 0);*/
            const uintptr_t Task__Defer = findPattern(Patterns::GetPattern("Task_Defer"));
            foundOffsets += (Task__Defer != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t Task__Spawn = findPattern(Patterns::GetPattern("Task_Spawn"));
            foundOffsets += (Task__Spawn != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t LuaVM__Load = Xrefs_scan("oldResult, moduleRef", 0x48, 6);
            foundOffsets += (LuaVM__Load != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t GetGlobalStateForInstance = Xrefs_scan("Script Start", 0x4C, 0, 2);
            foundOffsets += (GetGlobalStateForInstance != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t DecryptState = Xrefs_scan("Script Start", 0x4C, 0, 1);
            foundOffsets += (DecryptState != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t DecryptState_offets = Xrefs_scan("Script Start", 0x4C, 0, 0, 0, "DecryptState_offets");
            foundOffsets += (DecryptState_offets != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t GlobalState_offets = Xrefs_scan("Script Start", 0x4C, 0, 0, 0, "GlobalState_offets");
            foundOffsets += (GlobalState_offets != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t PushInstance = findPattern(Patterns::GetPattern("PushInstance"));
            foundOffsets += (PushInstance != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t Require = findPattern(Patterns::GetPattern("Require"));
            foundOffsets += (Require != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t Luau_Execute = findPattern(Patterns::GetPattern("Luau_Execute"));
            foundOffsets += (Luau_Execute != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t RawScheduler = findPattern(Patterns::GetPattern("RawScheduler"),true);
            foundOffsets += (RawScheduler != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t LuaO_nilobject = findPattern(Patterns::GetPattern("LuaO_nilobject"));
            foundOffsets += (LuaO_nilobject != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t LuaH_Dummynode = findPattern(Patterns::GetPattern("LuaH_Dummynode"));
            foundOffsets += (LuaH_Dummynode != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t KTable = findPattern(Patterns::GetPattern("KTable"));
            foundOffsets += (KTable != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t EnableLoadModule = findPattern(Patterns::GetPattern("EnableLoadModule"));
            foundOffsets += (EnableLoadModule != 0); showProgressBar(foundOffsets, totalScans);

            //// New offsets
            const uintptr_t dumpsetinsert = dump_setinsert();
            foundOffsets += (dumpsetinsert != 0); showProgressBar(foundOffsets, totalScans);

            const uintptr_t dumpthreadmap = dump_threadmap();
            foundOffsets += (dumpthreadmap != 0); showProgressBar(foundOffsets, totalScans);

            std::cout << "\nScanning complete! Found offsets: " << foundOffsets << "/" << totalScans << std::endl;

            // Generate dump file
            std::stringstream report;
            report << "\n"
                << "namespace Update {\n"
                << "const uintptr_t dumpsetinsert             = REBASE(0x" << std::hex << to_hex(dumpsetinsert) << ");\n"
                << "const uintptr_t dumpthreadmap             = REBASE(0x" << std::hex << to_hex(dumpthreadmap) << ");\n"
                << "const uintptr_t Print                     = REBASE(0x" << std::hex << to_hex(rebase(Print)) << ");\n"
                << "const uintptr_t RawScheduler              = REBASE(0x" << to_hex(rebase(RawScheduler)) << ");\n"
                << "const uintptr_t GetGlobalStateForInstance = REBASE(0x" << to_hex(rebase(GetGlobalStateForInstance)) << ");\n"
                << "const uintptr_t DecryptState              = REBASE(0x" << to_hex(rebase(DecryptState)) << ");\n"
                << "const uintptr_t LuaVM__Load               = REBASE(0x" << to_hex(rebase(LuaVM__Load)) << ");\n"
                << "const uintptr_t Require                   = REBASE(0x" << to_hex(rebase(Require)) << ");\n"
                << "const uintptr_t Luau_Execute              = REBASE(0x" << to_hex(rebase(Luau_Execute)) << ");\n"
                << "const uintptr_t Task__Defer               = REBASE(0x" << to_hex(rebase(Task__Defer)) << ");\n"
                << "const uintptr_t Task__Spawn               = REBASE(0x" << to_hex(rebase(Task__Spawn)) << ");\n"
                << "const uintptr_t LuaO_nilobject            = REBASE(0x" << std::hex << to_hex(rebase(findPattern(Patterns::GetPattern("LuaO_nilobject")))) << ");\n"
                << "const uintptr_t LuaH_Dummynode            = REBASE(0x" << std::hex << to_hex(rebase(findPattern(Patterns::GetPattern("LuaH_Dummynode")))) << ");\n"
                << "const uintptr_t KTable                    = REBASE(0x" << std::hex << to_hex(rebase(findPattern(Patterns::GetPattern("KTable")))) << ");\n"
                << "const uintptr_t EnableLoadModule          = REBASE(0x" << std::hex << to_hex(rebase(findPattern(Patterns::GetPattern("EnableLoadModule")))) << ");\n\n"
                << "namespace ScriptContext {\n"
                << "    const uintptr_t GlobalState = 0x" << to_hex(GlobalState_offets) << ";\n"
                << "    const uintptr_t DecryptState = 0x" << to_hex(DecryptState_offets) << ";\n"
                << "}\n"
                << "namespace ExtraSpace {\n"
                << "    const uintptr_t Identity      = 0x30;\n"
                << "    const uintptr_t Capabilities  = 0x48;\n"
                << "}\n";

            std::ofstream out_file("dump_report.cpp");
            if (out_file.is_open()) {
                out_file << report.str();
                out_file.close();

                if (Globals::CloseGameAfterDump)
                {
                    CloseRoblox();
                }
                

                log(LogColor::Cyan, "[*] Dump written to dump_report.cpp");
                
#ifdef _WIN32
                system("start dump_report.cpp");
#endif
            }
            else {
                log(LogColor::Red, "[-] Failed to write dump report.");
            }
        }
    }



}
