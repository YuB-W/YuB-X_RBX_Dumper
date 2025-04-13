#include "../../YuBCore.hpp"
#include <iostream>
#include <filesystem>


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

int main() {

    OpenRoblox();

    WaitForRobloxWindow();

    DWORD pid = YuBCore::GetProcessIdByName(L"RobloxPlayerBeta.exe");
    if (!pid || !YuBCore::attach(pid, "RobloxPlayerBeta.exe")) return 1;

    //YuBCore::Xrefs_scan(myString, opcode, /*skipCallDown=*/1, /*skipCallUp=*/2);

    YuBCore::Xrefs_scan("Video recording started" , 0x48, 0);
    YuBCore::Xrefs_scan("Script Start" , 0x4C , 0 , 2);
    YuBCore::Xrefs_scan("Maximum re-entrancy depth (%i) exceeded calling task.defer", 0x48 , 0 , 6);
    YuBCore::Xrefs_scan("oldResult,", 0, 6 , 0);
    YuBCore::Xrefs_scan("LuauWatchdog" , 0, 2 , 0);

    CloseRoblox();
    return 0;
}


