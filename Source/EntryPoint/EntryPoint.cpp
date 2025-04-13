#include "../../YuBCore.hpp"
#include <iostream>
#include <filesystem>
using namespace YuBCore;


std::string GetCurrentUserName() {
    char buffer[256];
    DWORD size = sizeof(buffer);
    if (GetUserNameA(buffer, &size)) {
        return std::string(buffer);
    }
    return ""; 
}

void OpenRoblox() {
    std::string userName = GetCurrentUserName();
    if (userName.empty()) {
        std::cout << "Failed to retrieve the user name." << std::endl;
        return;
    }

    const std::string basePath = "C:\\Users\\" + userName + "\\AppData\\Local\\";
    const std::string robloxExecutable = "RobloxPlayerBeta.exe";

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(basePath)) {
            if (entry.path().filename() == robloxExecutable) {
                std::cout << "Found Roblox at: " << entry.path() << std::endl;
                ShellExecuteA(NULL, "open", entry.path().string().c_str(), NULL, NULL, SW_SHOWNORMAL);
                return;
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
    }

    std::cout << "Roblox not found in the specified directory." << std::endl;
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

//YuBCore::Xrefs_scan(myString, opcode, /*skipCallDown=*/1, /*skipCallUp=*/2);

int main() {

    OpenRoblox();
    WaitForRobloxWindow();

    DWORD pid = YuBCore::GetProcessIdByName(L"RobloxPlayerBeta.exe");
    //YuBCore::SuspendThreads(pid);
    if (!pid || !YuBCore::attach(pid, "RobloxPlayerBeta.exe")) return 1;


    //YuBCore::Xrefs_scan("Video recording started",0x48,0,0);
    //YuBCore::Xrefs_scan("Maximum re-entrancy depth (%i) exceeded calling task.defer",0x48,0,6);
    //YuBCore::Xrefs_scan("LuauWatchdog",0x48,2,0);
    //YuBCore::Xrefs_scan("Script Start", 0x4C, 0, 2);


    const uintptr_t Print = rebase(Xrefs_scan("Current identity is %d", 0x48, 0, 0));
    const uintptr_t Task__Defer = rebase(YuBCore::Xrefs_scan("cannot %s non-suspended coroutine with arguments",0x48, 0, 5, 0, true)); // base_re for debug and if your ida is rebased to 0x400000
    const uintptr_t RawScheduler = rebase(Xrefs_scan("ClusterPacketCacheTaskQueue", 0x48, 0, 0, 0, true));
    const uintptr_t ScriptStart = rebase(Xrefs_scan("Script Start", 0x4C, 0, 2));
    const uintptr_t LuaVM__Load = rebase(Xrefs_scan("oldResult,", 0x48, 6, 0));

    const uintptr_t GetGlobalStateForInstance = rebase(0xEF0540); // Static (no string ref)
    const uintptr_t DecryptState = rebase(0xC92180); // Static (no string ref)


    std::stringstream report;
    report << "\n"
        << "const uintptr_t Print = REBASE(0x" << std::hex << Print << "); // Current identity is %d\n"
        << "const uintptr_t RawScheduler = REBASE(0x" << std::hex << RawScheduler << "); // ClusterPacketCacheTaskQueue\n"
        << "const uintptr_t GetGlobalStateForInstance = REBASE(0x" << std::hex << GetGlobalStateForInstance << ");\n"
        << "const uintptr_t DecryptState = REBASE(0x" << std::hex << DecryptState << ");\n"
        << "const uintptr_t LuaVM__Load = REBASE(0x" << std::uppercase << std::hex << LuaVM__Load << "); // oldResult, moduleRef = ...\n"
        << "const uintptr_t Task__Defer = REBASE(0x" << std::hex << Task__Defer << "); // task.defer\n"
        << "// YUBX::Core Dumper Finished!\n";

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
        #elif __APPLE__
                system("open dump_report.txt");
        #else
                system("xdg-open dump_report.txt");
        #endif
    }
    else {
        log(LogColor::Red, "[-] Failed to save report to file.");
        std::this_thread::sleep_for(std::chrono::minutes(1));
        return 0;
    }

    CloseRoblox();
}


