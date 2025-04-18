#include <iostream>
#include <chrono>

#include "../../YuBCore.hpp"



using namespace YuBCore;

int main() {
	//YuBCore::LaunchRobloxGame("17574618959");
	//YuBCore::WaitForRobloxWindow();
	//YuBCore::msgbox("YuB-X Dumper", "Byfron Who?");
    auto start = std::chrono::high_resolution_clock::now();
    YuBCore::dump();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "[*] dump() completed in " << duration.count() << " seconds." << std::endl;
}

