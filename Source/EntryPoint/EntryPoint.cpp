#include <iostream>
#include <chrono> 
#include "../../YuBCore.hpp"
#include "../../Globals.hpp"

#include <conio.h>
#include <windows.h>




#include <iostream>
#include <conio.h>
#include <windows.h>
#include <chrono>


HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

void clearConsole() {
    system("cls"); // Clears console when needed
}

void setCursorPosition(int x, int y) {
    COORD coord;
    coord.X = x;
    coord.Y = y;
    SetConsoleCursorPosition(hConsole, coord);
}

void setConsoleColor(bool state) {
    SetConsoleTextAttribute(hConsole, state ? 10 : 12); // Green = ON, Red = OFF
}

void getConsoleSize(int& width, int& height) {
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    width = csbi.dwSize.X;
    height = csbi.dwSize.Y;
}

void displayMenu(int selected) {
    int width, height;
    getConsoleSize(width, height);
    int centerY = height / 2 - 2;

    setCursorPosition(width / 2 - 7, centerY);
    std::cout << "Navigation Menu:";

    std::string options[] = { "Dump Offsets", "Settings", "Exit" };
    for (int i = 0; i < 3; ++i) {
        setCursorPosition(width / 2 - 6, centerY + i + 2);
        std::cout << (i == selected ? "> " : "  ") << options[i] << (i == selected ? " <" : "  ");
    }
}


void displaySettings(int selected) {
    int width, height;
    getConsoleSize(width, height);
    int centerY = height / 2 - 3;

    setCursorPosition(width / 2 - 6, centerY);
    std::cout << "Settings:";

    std::string options[] = { "Xref Debug", "Start Game Before Dump", "Close Game After Dump" };

    for (int i = 0; i < 3; ++i) {
        setCursorPosition(width / 2 - 8, centerY + i + 2);

        // Highlight the selected option
        setConsoleColor(i == selected);
        std::cout << options[i] << " : ";

        // Determine setting state
        bool settingState = (i == 0 ? Globals::XrefDebug :
            i == 1 ? Globals::StartGameBeforeDump :
            Globals::CloseGameAfterDump);

        // Set the ON/OFF position correctly to align all to the right
        int statePosition = width / 2 + 18; // Adjust this value for better alignment

        setCursorPosition(statePosition, centerY + i + 2); // Move to ON/OFF position
        std::cout << "    ";  // Ensures "ON" doesn't leave parts of "OFF" behind

        setCursorPosition(statePosition, centerY + i + 2); // Properly overwrite
        setConsoleColor(settingState);
        std::cout << (settingState ? "ON " : "OFF");

        setConsoleColor(true); // Reset color
    }
}




void settingsMenu() {
    clearConsole(); // Clears console when entering settings
    int selectedSetting = 0;
    char key;

    while (true) {
        displaySettings(selectedSetting);
        key = _getch();

        if (key == 72) // Up arrow
            selectedSetting = (selectedSetting - 1 + 3) % 3;
        else if (key == 80) // Down arrow
            selectedSetting = (selectedSetting + 1) % 3;
        else if (key == 13) { // Enter key to toggle setting
            if (selectedSetting == 0)
                Globals::XrefDebug = !Globals::XrefDebug;
            else if (selectedSetting == 1)
                Globals::StartGameBeforeDump = !Globals::StartGameBeforeDump;
            else
                Globals::CloseGameAfterDump = !Globals::CloseGameAfterDump;
        }
        else if (key == 27) { // Escape key to exit settings
            clearConsole(); // Clears screen properly before returning to main menu
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7); // Reset text color to white
            break;
        }
    }
}



int DumpMain() {
    clearConsole(); // Clears console only when switching to dumping

    auto start = std::chrono::high_resolution_clock::now();
    YuBCore::log(YuBCore::LogColor::Green, "[*] YuB-X started!");
    YuBCore::dump(); // dump offsets

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    
    std::cout << "[*] dump() completed in " << duration.count() << " seconds." << std::endl;

    YuBCore::log(YuBCore::LogColor::Green, "[*] YuB-X finished!");
    YuBCore::log(YuBCore::LogColor::Green, "[*] Press any key to exit...");
    std::cin.get();

    return 0;
}

int main() {
    int selectedOption = 0;
char key;

while (true) {
    displayMenu(selectedOption);
    key = _getch();

    if (key == 72) // Up arrow
        selectedOption = (selectedOption - 1 + 3) % 3;
    else if (key == 80) // Down arrow
        selectedOption = (selectedOption + 1) % 3;
    else if (key == 13) { // Enter key to select option
        if (selectedOption == 1) {
            clearConsole();
            settingsMenu(); // Open settings menu
            continue; // Return to menu after exiting settings
        }
        else if (selectedOption == 2) {
            clearConsole();
            std::cout << "Exiting...\n";
            return 0; // Exit properly
        }
        else {
            DumpMain(); // Run dump process
            return 0; // Exit properly
        }
    }
    else if (key == 27) { // ESC key pressed
        clearConsole();
        std::cout << "Returning to main menu...\n";
        continue; // Loop back to main menu
    }
}

    return 0;
}
