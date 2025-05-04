#include <iostream>
#include <string>

namespace Patterns {
    const std::string Task_Defer = "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 56 48 81 EC ? ? ? ? 48 8B F9 80 3D";
    const std::string Task_Spawn = "48 89 5C 24 ? 55 56 57 48 81 EC ? ? ? ? 48 8B D9 80 3D";
    const std::string PushInstance = "48 89 5C 24 08 57 48 83 EC ? 48 8B FA 48 8B D9 E8 ? ? ? ? 84 C0 74 ? 48 8B D7 48 8B CB 48 8B 5C 24";
    const std::string Require = "0F B6 86 ? ? ? ? 48 89 2F";
    const std::string Luau_Execute = "80 79 06 00 0F 85 ? ? ? ? E9 ? ? ? ?";
    const std::string RawScheduler = "48 89 05 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? EB ? 39 05 ? ? ? ? 7E ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 83 3D ? ? ? ? ? 75 ? B9 ? ? ? ? E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 89 44 24 ? 48 8B C8 E8 ? ? ? ? 90 48 89 05 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B 0D ? ? ? ? 8B D3";
    const std::string LuaO_nilobject = "48 8d 3d ? ? ? ? 48 3b d7";
    const std::string LuaH_Dummynode = "48 8d 3d ? ? ? ? 48 8B D9 48 39";
    const std::string KTable = "48 8d 0d ? ? ? ? 48 8d 54 24 ? 48 8b 04 c1";
    const std::string EnableLoadModule = "4C 8D 05 ? ? ? ? 41 B9 ? ? ? ? 48 8D 15 ? ? ? ? E8 ? ? ? ? 48 83 C4 ? C3 CC CC CC CC CC CC CC 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 33 FF";

    std::string GetPattern(const std::string& patternName) {
        if (patternName == "Task_Defer") return Task_Defer;
        if (patternName == "Task_Spawn") return Task_Spawn;
        if (patternName == "PushInstance") return PushInstance;
        if (patternName == "Require") return Require;
        if (patternName == "Luau_Execute") return Luau_Execute;
        if (patternName == "RawScheduler") return RawScheduler;
        if (patternName == "LuaO_nilobject") return LuaO_nilobject;
        if (patternName == "LuaH_Dummynode") return LuaH_Dummynode;
        if (patternName == "KTable") return KTable;
        if (patternName == "EnableLoadModule") return EnableLoadModule;

        return "Pattern not found!";
    }

}

