
namespace YuBCore {
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING, * PUNICODE_STRING;

    typedef struct _OBJECT_ATTRIBUTES {
        ULONG           Length;
        HANDLE          RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG           Attributes;
        PVOID           SecurityDescriptor;
        PVOID           SecurityQualityOfService;
    } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) \
        do { \
            (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
            (p)->RootDirectory = r; \
            (p)->Attributes = a; \
            (p)->ObjectName = n; \
            (p)->SecurityDescriptor = s; \
            (p)->SecurityQualityOfService = NULL; \
        } while (0)

#define STATUS_OBJECT_TYPE_MISMATCH ((NTSTATUS)0xC0000024L)

    typedef NTSTATUS(NTAPI* PNtOpenSection)(
        PHANDLE            SectionHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
        );



    enum class XrefType {
        ANY, CODE, DATA
    };

    struct CallInstruction {
        uintptr_t address;
        uintptr_t target;
        size_t size;
    };

    HANDLE hProcess = nullptr;
    uintptr_t baseAddress = 0;
    SIZE_T baseSize = 0;
    std::mutex memoryMutex;

    uintptr_t rebase(uintptr_t address) {
        if (baseAddress == 0) return 0;
        return (address - baseAddress); //+0x400000
    }

    uintptr_t base(uintptr_t address) {
        if (baseAddress == 0) return 0;
        return (address + baseAddress);
    }


    DWORD GetProcessIdByName(const std::wstring& name) {
        PROCESSENTRY32W entry = { 0 };
        entry.dwSize = sizeof(entry);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return 0;
    }

#define MAX_SYM_NAME 256

    enum class LogColor {
        Default = 7,
        Green = 10,
        Yellow = 14,
        Red = 12,
        Cyan = 11
    };

    void setColor(LogColor color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<WORD>(color));
    }

    void log(LogColor color, const std::string& message, const std::string& logfile = "dump_report.log") {
        auto now = std::chrono::system_clock::now();
        auto timeT = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&timeT);

        std::ostringstream oss;
        oss << "[" << std::put_time(&tm, "%H:%M:%S") << "] " << message;

        setColor(color);
        std::cout << oss.str() << std::endl;
        setColor(LogColor::Default);

        std::ofstream logFile(logfile, std::ios_base::app);
        if (logFile.is_open()) {
            logFile << oss.str() << std::endl;
            logFile.close();
        }
        else {
            std::cerr << "Error opening log file!" << std::endl;
        }
    }


    std::string to_hex(uintptr_t addr) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << addr;
        return ss.str();
    }

    uintptr_t from_hex(const std::string& hexStr) {
        uintptr_t value;
        std::stringstream ss;
        ss << std::hex << hexStr;
        ss >> value;
        return value;
    }
}