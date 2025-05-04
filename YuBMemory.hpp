#pragma once
#include <Windows.h>
#include <memory>

class TMEM {
private:
    HANDLE process_handle;

public:
    explicit TMEM(DWORD pid) {
        process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }

    ~TMEM() {
        if (process_handle)
            CloseHandle(process_handle);
    }

    template<typename T>
    T read(uintptr_t address) const {
        T buffer{};
        ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(address), &buffer, sizeof(T), nullptr);
        return buffer;
    }

    template<typename T>
    bool write(uintptr_t address, const T& value) const {
        return WriteProcessMemory(process_handle, reinterpret_cast<LPVOID>(address), &value, sizeof(T), nullptr);
    }

    uintptr_t allocate(size_t size, DWORD protect = PAGE_EXECUTE_READWRITE) const {
        return reinterpret_cast<uintptr_t>(VirtualAllocEx(process_handle, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect));
    }

    bool free(uintptr_t address) const {
        return VirtualFreeEx(process_handle, reinterpret_cast<LPVOID>(address), 0, MEM_RELEASE);
    }

    HANDLE handle() const {
        return process_handle;
    }

    bool is_valid_pointer(uintptr_t address) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(process_handle, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
            return false;

        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_GUARD)
            return false;

        return true;
    }

    static std::unique_ptr<TMEM> setup(DWORD ppid) {
        return std::make_unique<TMEM>(ppid);
    }
};
