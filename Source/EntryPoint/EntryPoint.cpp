#include "../../YuBCore.hpp"
using namespace YuBCore;

int main() {

    LaunchRobloxGame("17574618959");

    WaitForRobloxWindow();

    DWORD pid = YuBCore::GetProcessIdByName(L"RobloxPlayerBeta.exe");

    //YuBCore::SuspendThreads(pid);

    if (!pid || !YuBCore::attach(pid, "RobloxPlayerBeta.exe")) return 1;

    YuBCore::dump();

    CloseRoblox();
}
