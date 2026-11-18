#if defined(CM_PE_PAYLOAD)
#define CM_PAYLOAD
#include "windows-preflight.c"
#include <winver.h>

#ifndef CM_PE_FORWARD
__declspec(dllexport) int WINAPI cm_mod_entry_v1(void) {
    DWORD ignored = 0;
    return GetFileVersionInfoSizeW(L"C:\\cm-pe-nonexistent-version-input", &ignored) == 0 ? 41 : 77;
}
__declspec(dllexport) int WINAPI cm_mod_entry_v2(void) { return cm_mod_entry_v1(); }
#endif

#elif defined(CM_PE_POISON)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>

__declspec(dllexport) DWORD WINAPI cm_pe_fake_version(LPCWSTR path, LPDWORD handle) {
    (void)path;
    if (handle) *handle = 0;
    return 777;
}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t path[4096];
        DWORD length = GetEnvironmentVariableW(L"CM_PE_POISON_MARKER", path, 4096), written = 0;
        if (!length || length >= 4096) return FALSE;
        HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) return FALSE;
        BOOL ok = WriteFile(file, "poison77", 8, &written, NULL);
        CloseHandle(file);
        if (!ok || written != 8) return FALSE;
    }
    return TRUE;
}

#else
#define wmain cm_existing_pin_control_main
#include "windows-preflight.c"
#undef wmain

#define system_module cm_windows_system_module
#define system_dependencies cm_windows_system_dependencies

int wmain(int argc, wchar_t **argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
#if defined(_M_ARM64) && !defined(_M_ARM64EC)
    const USHORT expected_machine = IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_X64) && !defined(_M_ARM64EC)
    const USHORT expected_machine = IMAGE_FILE_MACHINE_AMD64;
#else
#error Native ARM64 or AMD64 MSVC is required
#endif
    USHORT process_machine, native_machine;
    if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine)
        || process_machine != IMAGE_FILE_MACHINE_UNKNOWN || native_machine != expected_machine)
        return rejected("native-architecture", ERROR_BAD_EXE_FORMAT);
    if (argc != 7) return rejected("arguments", ERROR_INVALID_PARAMETER);
    BOOL unsafe_search = !wcscmp(argv[1], L"unsafe");
    BOOL preloaded = !wcscmp(argv[1], L"unchecked-preloaded") || !wcscmp(argv[1], L"guarded-preloaded");
    BOOL guarded = !wcscmp(argv[1], L"guarded") || !wcscmp(argv[1], L"guarded-preloaded");
    if (!unsafe_search && !preloaded && !guarded && wcscmp(argv[1], L"system32"))
        return rejected("mode", ERROR_INVALID_PARAMETER);
    const char *entry = !wcscmp(argv[4], L"cm_mod_entry_v1") ? "cm_mod_entry_v1"
        : !wcscmp(argv[4], L"cm_mod_entry_v2") ? "cm_mod_entry_v2" : NULL;
    if (!entry) return rejected("entry", ERROR_INVALID_PARAMETER);
    Pin p;
    if (!pin(&p, argv[2])) return rejected(p.file_attempted ? "pin-file" : "pin-ancestors", GetLastError());
    if (!sha256(p.file, argv[3])) return rejected("payload-hash", ERROR_INVALID_DATA);
    if (preloaded) {
        if (GetModuleHandleW(L"version.dll")) return rejected("preload-control-already-loaded", ERROR_INVALID_DATA);
        HMODULE poison = LoadLibraryExW(argv[6], NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!poison || GetModuleHandleW(L"version.dll") != poison || system_module(poison))
            return rejected("preload-control", GetLastError());
        puts("{\"status\":\"preloaded\",\"poison_executed\":true,\"payload_executed\":false}");
    }
    int dependency_count = 0;
    if (guarded) {
        dependency_count = system_dependencies(argv[5]);
        if (dependency_count < 0) {
            printf("{\"status\":\"rejected\",\"gate\":\"system-dependency-identity\",\"preload_executed\":%s,\"payload_executed\":false}\n",
                preloaded ? "true" : "false");
            return 2;
        }
    }
    HANDLE current = CreateFileW(p.path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    FILE_ID_INFO id;
    LARGE_INTEGER size;
    if (current == INVALID_HANDLE_VALUE || !GetFileInformationByHandleEx(current, FileIdInfo, &id, sizeof(id))
        || !GetFileSizeEx(current, &size) || memcmp(&id, &p.id, sizeof(id)) || size.QuadPart != p.size.QuadPart)
        return rejected("pinned-identity", ERROR_INVALID_DATA);
    CloseHandle(current);
    HMODULE module = unsafe_search ? LoadLibraryExW(p.path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH)
        : LoadLibraryExW(p.path, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) {
        printf("{\"status\":\"failed\",\"gate\":\"LoadLibraryExW\",\"error\":%lu,\"payload_load_attempted\":true}\n", GetLastError());
        return 2;
    }
    FARPROC address = GetProcAddress(module, entry);
    typedef int (WINAPI *Entry)(void);
    Entry function = NULL;
    _Static_assert(sizeof(function) == sizeof(address), "entry pointer size");
    memcpy(&function, &address, sizeof(function));
    if (!function) return 2;
    int value = function();
    if (guarded && system_dependencies(argv[5]) < 0) return 2;
    printf("{\"status\":\"loaded\",\"entry_value\":%d,\"dependencies\":%d,\"guarded\":%s,\"payload_executed\":true}\n",
        value, dependency_count, guarded ? "true" : "false");
    return value == 41 || value == 77 ? 0 : 2;
}
#endif
