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
#include <chrono>
#include "YuBUtils.hpp"
#include "YuBRoblox.hpp"
#include "YuBXRef.hpp"
#include "YuBMemory.hpp"
#include "Dumper.hpp"
#include "Patterns.hpp"

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

    std::string GetRobloxExePath() {
        std::string exePath;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return exePath;

        PROCESSENTRY32 pe = { 0 };
        pe.dwSize = sizeof(pe);

        if (Process32First(hSnap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "RobloxPlayerBeta.exe") == 0) {
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProc) {
                        char buf[MAX_PATH];
                        DWORD sz = MAX_PATH;
                        if (QueryFullProcessImageNameA(hProc, 0, buf, &sz)) {
                            exePath = buf;
                            CloseHandle(hProc);
                            break;
                        }
                        CloseHandle(hProc);
                    }
                }
            } while (Process32Next(hSnap, &pe));
        }

        CloseHandle(hSnap);
        return exePath;
    }

    std::string ExtractRobloxVersion(const std::string& exePath) {
        namespace fs = std::filesystem;
        fs::path path(exePath);
        fs::path parent = path.parent_path();
        fs::path grandparent = parent.parent_path();

        auto starts_with_version = [](const std::string& folder) {
            return folder.size() > 8 &&
                std::equal(folder.begin(), folder.begin() + 8, "version-", [](char a, char b) {
                return std::tolower(a) == std::tolower(b);
                    });
            };

        std::string folder = parent.filename().string();
        if (starts_with_version(folder))
            return folder;

        std::string upper = grandparent.filename().string();
        if (starts_with_version(upper))
            return upper;

        return "unknown";
    }


    int dump() {
        log(LogColor::Green, "[!] YuB-X Dumper!");

        if (Globals::StartGameBeforeDump)
            LaunchRobloxGame("17574618959");

        WaitForRobloxProcess();

        if (!check_is_running("RobloxPlayerBeta.exe"))
            return 0;

        DWORD pid = YuBCore::GetProcessIdByName(L"RobloxPlayerBeta.exe");
        if (!pid || !YuBCore::attach(pid, "RobloxPlayerBeta.exe"))
            return 0;

        auto process = TMEM::setup(pid);
        dumper->bind(std::move(process));

        log(LogColor::Green, "[!] Start Dump...");
        std::cout << "\nProgress:\n";

        int totalScans = 18;
        int foundOffsets = 0;

        // === SCANS ===
        const uintptr_t Print = Xrefs_scan("Current identity is %d", 0x48, 1, 0);
        foundOffsets += (Print != 0);             showProgressBar(foundOffsets, totalScans);

        const uintptr_t LuaVM__Load = Xrefs_scan("oldResult, moduleRef", 0x48, 12);
        foundOffsets += (LuaVM__Load != 0);       showProgressBar(foundOffsets, totalScans);

        const uintptr_t GetGlobalStateForInstance = Xrefs_scan("Script Start", 0x48, 0, 1);
        foundOffsets += (GetGlobalStateForInstance != 0); showProgressBar(foundOffsets, totalScans);

        const uintptr_t PushInstance = fastfindPattern(Patterns::GetPattern("PushInstance"));
        foundOffsets += (PushInstance != 0);      showProgressBar(foundOffsets, totalScans);

        const uintptr_t Luau_Execute = fastfindPattern(Patterns::GetPattern("Luau_Execute"));
        foundOffsets += (Luau_Execute != 0);      showProgressBar(foundOffsets, totalScans);

        const uintptr_t RawScheduler = fastfindPattern(Patterns::GetPattern("RawScheduler"), true);
        foundOffsets += (RawScheduler != 0);      showProgressBar(foundOffsets, totalScans);

        const uintptr_t LuaO_nilobject = fastfindPattern(Patterns::GetPattern("LuaO_nilobject"), true, "unk");
        foundOffsets += (LuaO_nilobject != 0);    showProgressBar(foundOffsets, totalScans);

        const uintptr_t LuaH_Dummynode = fastfindPattern(Patterns::GetPattern("LuaH_Dummynode"), true, "unk");
        foundOffsets += (LuaH_Dummynode != 0);    showProgressBar(foundOffsets, totalScans);

        const uintptr_t KTable = fastfindPattern(Patterns::GetPattern("KTable"), true, "unk");
        foundOffsets += (KTable != 0);            showProgressBar(foundOffsets, totalScans);

        const uintptr_t EnableLoadModule = Xrefs_scan("EnableLoadModule", 0x48, 1, 0, 0, "FFlag");
        foundOffsets += (EnableLoadModule != 0);  showProgressBar(foundOffsets, totalScans);

        const uintptr_t DebugCheckRenderThreading = Xrefs_scan("DebugCheckRenderThreading", 0x48, 1, 0, 0, "FFlag");
        foundOffsets += (DebugCheckRenderThreading != 0); showProgressBar(foundOffsets, totalScans);

        const uintptr_t RenderDebugCheckThreading2 = Xrefs_scan("RenderDebugCheckThreading2", 0x48, 1, 0, 0, "FFlag");
        foundOffsets += (RenderDebugCheckThreading2 != 0); showProgressBar(foundOffsets, totalScans);

        const uintptr_t DisableCorescriptLoadstring = Xrefs_scan("DisableCorescriptLoadstring", 0x48, 1, 0, 0, "FFlag");
        foundOffsets += (DisableCorescriptLoadstring != 0); showProgressBar(foundOffsets, totalScans);

        const uintptr_t LockViolationInstanceCrash = Xrefs_scan("LockViolationInstanceCrash", 0x48, 1, 0, 0, "FFlag");
        foundOffsets += (LockViolationInstanceCrash != 0); showProgressBar(foundOffsets, totalScans);

        const uintptr_t LockViolationScriptCrash = Xrefs_scan("LockViolationScriptCrash", 0x48, 1, 0, 0, "FFlag");
        foundOffsets += (LockViolationScriptCrash != 0); showProgressBar(foundOffsets, totalScans);

        const uintptr_t LuaStepIntervalMsOverrideEnabled = Xrefs_scan("LuaStepIntervalMsOverrideEnabled", 0x48, 1, 0, 0, "FFlag");
        foundOffsets += (LuaStepIntervalMsOverrideEnabled != 0); showProgressBar(foundOffsets, totalScans);

        const uintptr_t TaskSchedulerTargetFps = Xrefs_scan("TaskSchedulerTargetFps", 0x48, 1, 0, 0, "FFlag");
        foundOffsets += (TaskSchedulerTargetFps != 0); showProgressBar(foundOffsets, totalScans);

        const uintptr_t WndProcessCheck = Xrefs_scan("WndProcessCheck", 0x48, 1, 0, 0, "FFlag");
        foundOffsets += (WndProcessCheck != 0); showProgressBar(foundOffsets, totalScans);


        const uintptr_t dumpsetinsert = dump_setinsert();
        foundOffsets += (dumpsetinsert != 0);     showProgressBar(foundOffsets, totalScans);

        const uintptr_t dumpthreadmap = dump_bitmap();
        foundOffsets += (dumpthreadmap != 0);     showProgressBar(foundOffsets, totalScans);

        std::cout << "\nScanning complete! Found offsets: " << foundOffsets << "/" << totalScans << std::endl;

        std::string exePath = GetRobloxExePath();
        std::string version = ExtractRobloxVersion(exePath);
        std::ostringstream datetime;///
        {
            auto now = std::chrono::system_clock::now();
            std::time_t now_c = std::chrono::system_clock::to_time_t(now);
            std::tm now_tm;
#ifdef _WIN32
            localtime_s(&now_tm, &now_c);
#else
            localtime_r(&now_c, &now_tm);
#endif
            datetime << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S");
        }
        std::ostringstream report;
        report << "// YuB-X Version: " << "Public" << "\n";
        report << "// Discord: " << "https://discord.com/invite/yubx" << "\n";

        report << "// Roblox Version: " << version << "\n";
        report << "// Dump Time:      " << datetime.str() << "\n\n";

        report << "namespace Update {\n";
        report << "    const uintptr_t setinsert                 = REBASE(0x" << to_hex(dumpsetinsert) << ");\n";
        report << "    const uintptr_t bitmap                    = REBASE(0x" << to_hex(dumpthreadmap) << ");\n";
        report << "    const uintptr_t Print                     = REBASE(0x" << to_hex(rebase(Print)) << ");\n";
        report << "    const uintptr_t RawScheduler              = REBASE(0x" << to_hex(rebase(RawScheduler)) << ");\n";
        report << "    const uintptr_t GetGlobalStateForInstance = REBASE(0x" << to_hex(rebase(GetGlobalStateForInstance)) << ");\n";
        report << "    const uintptr_t LuaVM__Load               = REBASE(0x" << to_hex(rebase(LuaVM__Load)) << ");\n";
        report << "    const uintptr_t Luau_Execute              = REBASE(0x" << to_hex(rebase(Luau_Execute)) << ");\n";
        report << "    const uintptr_t LuaO_nilobject            = REBASE(0x" << to_hex(rebase(LuaO_nilobject)) << ");\n";
        report << "    const uintptr_t LuaH_Dummynode            = REBASE(0x" << to_hex(rebase(LuaH_Dummynode)) << ");\n";
        report << "    const uintptr_t KTable                    = REBASE(0x" << to_hex(rebase(KTable)) << ");\n";
        report << "    const uintptr_t EnableLoadModule          = REBASE(0x" << to_hex(rebase(EnableLoadModule)) << ");\n";
        report << "}\n\n";

        report << "namespace InternalFastFlags {\n";
        report << "    const uintptr_t EnableLoadModule                 = REBASE(0x" << to_hex(rebase(EnableLoadModule)) << ");\n";
        report << "    const uintptr_t DebugCheckRenderThreading        = REBASE(0x" << to_hex(rebase(DebugCheckRenderThreading)) << ");\n";
        report << "    const uintptr_t RenderDebugCheckThreading2       = REBASE(0x" << to_hex(rebase(RenderDebugCheckThreading2)) << ");\n";
        report << "    const uintptr_t DisableCorescriptLoadstring      = REBASE(0x" << to_hex(rebase(DisableCorescriptLoadstring)) << ");\n";
        report << "    const uintptr_t LockViolationInstanceCrash       = REBASE(0x" << to_hex(rebase(LockViolationInstanceCrash)) << ");\n";
        report << "    const uintptr_t LockViolationScriptCrash         = REBASE(0x" << to_hex(rebase(LockViolationScriptCrash)) << ");\n";
        report << "    const uintptr_t WndProcessCheck                  = REBASE(0x" << to_hex(rebase(WndProcessCheck)) << ");\n";
        report << "    const uintptr_t LuaStepIntervalMsOverrideEnabled = REBASE(0x" << to_hex(rebase(LuaStepIntervalMsOverrideEnabled)) << ");\n";
        report << "}\n";

        std::ofstream out_file("dump_report.cpp");
        if (out_file.is_open()) {
            out_file << report.str();
            out_file.close();

            if (Globals::CloseGameAfterDump)
                CloseRoblox();

            log(LogColor::Cyan, "[*] Dump written to dump_report.cpp");
#ifdef _WIN32
            system("start dump_report.cpp");
#endif
        }
        else {
            log(LogColor::Red, "[-] Failed to write dump report.");
        }

        return 0;
    }
}
