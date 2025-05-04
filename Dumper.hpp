#pragma once
#include "YuBMemory.hpp"
#include <string>

class TDumper {
public:
    auto dump_instance_name() -> uintptr_t {
        for (uintptr_t offset = 0x70; offset < 0x100; offset++) {
            auto ptr = process->read<uintptr_t>(dm + offset);
            if (!process->is_valid_pointer(ptr)) continue;

            auto str = process->read<std::string>(ptr);
            if (str == "LuaApp") return offset;
        }
        return 0;
    }

    auto dump_parent() -> uintptr_t {
        auto name_offset = dump_instance_name();
        for (uintptr_t offset = 0x50; offset < 0x100; offset++) {
            auto ptr = process->read<uintptr_t>(s + offset);
            if (!process->is_valid_pointer(ptr)) continue;

            auto ptr2 = process->read<uintptr_t>(ptr + name_offset);
            auto str = process->read<std::string>(ptr2);
            if (str == "LuaApp") return offset;
        }
        return 0;
    }

    auto dump_instance_children() -> uintptr_t {
        auto name_offset = dump_instance_name();
        for (uintptr_t offset = 0x80; offset < 0x100; offset++) {
            auto ptr = process->read<uintptr_t>(dm + offset);
            if (!process->is_valid_pointer(ptr)) continue;

            auto ptr2 = process->read<uintptr_t>(ptr);
            if (!process->is_valid_pointer(ptr2)) continue;

            auto ptr3 = process->read<uintptr_t>(ptr2);
            if (!process->is_valid_pointer(ptr3)) continue;

            auto str = process->read<std::string>(ptr3 + name_offset);
            if (str == "Workspace") return offset;
        }
        return 0;
    }

    auto dump_fake_(uintptr_t renderview) -> uintptr_t {
        for (uintptr_t offset = 0x88; offset < 0x100; offset++) {
            auto ptr = process->read<uintptr_t>(renderview + offset);
            if (!process->is_valid_pointer(ptr)) continue;

            auto ptr1 = process->read<uintptr_t>(ptr);
            auto p1 = process->read<uintptr_t>(ptr1 + 0x18);
            auto p2 = process->read<uintptr_t>(ptr1 + 0x20);

            if (process->is_valid_pointer(p1) && process->is_valid_pointer(p2))
                return offset;
        }
        return 0;
    }

    auto dump_real_(uintptr_t fake) -> uintptr_t {
        auto name_offset = dump_instance_name();
        for (uintptr_t offset = 0x1B8; offset < 0x200; offset++) {
            auto ptr = process->read<uintptr_t>(fake + offset);
            auto ptr2 = process->read<uintptr_t>(ptr + name_offset);
            auto str = process->read<std::string>(ptr2);
            if (str == "LuaApp") return offset;
        }
        return 0;
    }

    auto set_scriptcontext(uintptr_t sc) -> void {
        s = sc;
    }

    auto set_datamodel(uintptr_t dam) -> void {
        dm = dam;
    }

    TMEM* operator->() {
        return process.get();
    }

    void bind(std::unique_ptr<TMEM> mem) {
        process = std::move(mem);
    }

private:
    uintptr_t s = 0;
    uintptr_t dm = 0;
    std::unique_ptr<TMEM> process = nullptr;
};

extern auto dumper = std::make_unique<TDumper>();