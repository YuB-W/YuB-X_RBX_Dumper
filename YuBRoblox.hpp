namespace YuBCore {
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

    bool IsRobloxRunning() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                std::string processName(pe.szExeFile);
                if (processName == "RobloxPlayerBeta.exe") {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return false;
    }

    void WaitForRobloxProcess() {
        std::cout << "[*] Waiting for Roblox process to start..." << std::endl;
        while (!IsRobloxRunning()) {
            std::this_thread::sleep_for(std::chrono::seconds(0));
        }
        std::cout << "[+] Roblox process is now running!" << std::endl;
    }
}