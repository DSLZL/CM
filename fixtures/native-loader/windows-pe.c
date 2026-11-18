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

#include <aclapi.h>
#include <sddl.h>
#include <winioctl.h>

static PSECURITY_DESCRIPTOR private_descriptor(const wchar_t *user, const wchar_t *permissions) {
    wchar_t dacl[1536], text[2048];
    PSECURITY_DESCRIPTOR descriptor = NULL;
    const wchar_t *marker = wcsstr(permissions, L"%ls");
    if (marker) {
        if (swprintf_s(dacl, 1536, L"%.*ls%ls%ls", (int)(marker - permissions), permissions, user, marker + 3) < 0)
            return NULL;
    } else if (wcscpy_s(dacl, 1536, permissions)) return NULL;
    if (swprintf_s(text, 2048, L"O:%ls%ls", user, dacl) < 0
        || !ConvertStringSecurityDescriptorToSecurityDescriptorW(text, SDDL_REVISION_1, &descriptor, NULL))
        return NULL;
    return descriptor;
}

static int private_fixture(const wchar_t *root, int change) {
    TOKEN_USER *user = cm_windows_user();
    wchar_t *sid = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    CmWindowsPin *parent = cm_windows_directory_open(root);
    const wchar_t *target = L"initial";
    int ok = 0;
    if (!parent || !user || !ConvertSidToStringSidW(user->User.Sid, &sid)) goto done;
    if (change) {
        target = L"private-dir";
        CmWindowsPin *child = cm_windows_child_open(parent, L"private-dir", 1);
        wchar_t path[4096];
        if (!child) goto done;
        wcscpy_s(path, 4096, child->path);
        descriptor = private_descriptor(sid, change == 1 ? L"D:P(A;;FA;;;WD)" : L"D:P(A;;FA;;;%ls)");
        HANDLE writer = CreateFileW(path, WRITE_DAC | READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        PACL dacl = NULL;
        BOOL present, defaulted;
        FILE_ID_INFO id, expected;
        ok = descriptor && writer != INVALID_HANDLE_VALUE
            && GetFileInformationByHandleEx(child->file, FileIdInfo, &expected, sizeof(expected))
            && GetFileInformationByHandleEx(writer, FileIdInfo, &id, sizeof(id))
            && !memcmp(&id, &expected, sizeof(id))
            && GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) && present && dacl;
        if (ok) {
            DWORD result = SetSecurityInfo(writer, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL);
            ok = result == ERROR_SUCCESS;
            if (!ok) SetLastError(result);
        }
        if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
        cm_windows_pin_free(child);
        goto done;
    }
    const struct {
        const wchar_t *name, *dacl;
        int directory, private;
    } cases[] = {
        {L"private-dir", L"D:P(A;;FA;;;%ls)", 1, 1},
        {L"private-file", L"D:P(A;;FA;;;%ls)", 0, 1},
        {L"read-only-file", L"D:P(A;;FR;;;%ls)", 0, 1},
        {L"everyone-file", L"D:P(A;;FA;;;%ls)(A;;FR;;;WD)", 0, 0},
        {L"everyone-dir", L"D:P(A;;FA;;;%ls)(A;;FR;;;WD)", 1, 0},
        {L"null-dacl", L"D:NO_ACCESS_CONTROL", 0, 0},
        {L"empty-dacl", L"D:P", 0, 0},
        {L"unprotected-file", L"D:(A;;FA;;;%ls)", 0, 0},
        {L"denied-ace", L"D:P(D;;0x2;;;WD)(A;;FA;;;%ls)", 0, 0},
        {L"inherited-ace", L"D:P(A;ID;FA;;;%ls)", 0, 0},
        {L"metadata-file", L"D:P(A;;FA;;;%ls)", 0, 1},
        {L"metadata-dir", L"D:P(A;OICI;FRFX;;;%ls)", 1, 1},
        {L"metadata-sparse", L"D:P(A;;FA;;;%ls)", 0, 1},
    };
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        target = cases[index].name;
        wchar_t path[4096];
        descriptor = private_descriptor(sid, cases[index].dacl);
        if (!descriptor || cm_windows_private_descriptor(descriptor, user->User.Sid) != cases[index].private
            || swprintf_s(path, 4096, L"%ls\\%ls", root, cases[index].name) < 0)
            goto done;
        SECURITY_ATTRIBUTES security = {sizeof(security), descriptor, FALSE};
        if (cases[index].directory) {
            if (!CreateDirectoryW(path, &security)) goto done;
        } else {
            BOOL sparse = !wcscmp(target, L"metadata-sparse");
            HANDLE file = CreateFileW(path, READ_CONTROL | (sparse ? GENERIC_WRITE : 0), 0, &security, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
            if (file == INVALID_HANDLE_VALUE) goto done;
            DWORD received = 0;
            BOOL configured = !sparse || DeviceIoControl(file, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &received, NULL);
            DWORD error = GetLastError();
            CloseHandle(file);
            if (!configured) { SetLastError(error); goto done; }
            if (!wcscmp(target, L"metadata-file") && !SetFileAttributesW(path,
                FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)) goto done;
        }
        LocalFree(descriptor); descriptor = NULL;
    }
    wchar_t mismatch[2048];
    target = L"foreign-owner-descriptor";
    if (swprintf_s(mismatch, 2048, L"O:WDD:P(A;;FA;;;%ls)", sid) < 0
        || !ConvertStringSecurityDescriptorToSecurityDescriptorW(mismatch, SDDL_REVISION_1, &descriptor, NULL)
        || cm_windows_private_descriptor(descriptor, user->User.Sid))
        goto done;
    ok = 1;
done: {
    DWORD error = GetLastError();
    if (descriptor) LocalFree(descriptor);
    if (sid) LocalFree(sid);
    free(user);
    if (parent) cm_windows_pin_free(parent);
    if (!ok) fwprintf(stderr, L"private fixture target=%ls change=%d\n", target, change);
    return ok ? 0 : rejected("private-fixture", error ? error : ERROR_INVALID_DATA);
}}

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
    if (argc == 3 && !wcscmp(argv[1], L"private-setup")) return private_fixture(argv[2], 0);
    if (argc == 3 && !wcscmp(argv[1], L"private-change")) return private_fixture(argv[2], 1);
    if (argc == 3 && !wcscmp(argv[1], L"private-restore")) return private_fixture(argv[2], 2);
    if (argc != 7) return rejected("arguments", ERROR_INVALID_PARAMETER);
    BOOL unsafe_search = !wcscmp(argv[1], L"unsafe");
    BOOL preloaded = !wcscmp(argv[1], L"unchecked-preloaded") || !wcscmp(argv[1], L"guarded-preloaded");
    BOOL trusted_release = !wcscmp(argv[1], L"trusted-release");
    BOOL guarded = !wcscmp(argv[1], L"guarded") || !wcscmp(argv[1], L"guarded-preloaded") || trusted_release;
    if (!unsafe_search && !preloaded && !guarded && wcscmp(argv[1], L"system32"))
        return rejected("mode", ERROR_INVALID_PARAMETER);
    const char *entry = !wcscmp(argv[4], L"cm_mod_entry_v1") ? "cm_mod_entry_v1"
        : !wcscmp(argv[4], L"cm_mod_entry_v2") ? "cm_mod_entry_v2" : NULL;
    if (!entry) return rejected("entry", ERROR_INVALID_PARAMETER);
    Pin p;
    if (!pin(&p, argv[2])) return rejected(p.file_attempted ? "pin-file" : "pin-ancestors", GetLastError());
    if (!sha256(p.file, argv[3])) return rejected("payload-hash", ERROR_INVALID_DATA);
    HMODULE trusted = NULL;
    if (trusted_release) {
        if (GetModuleHandleW(L"version.dll")) return rejected("trusted-control-already-loaded", ERROR_INVALID_DATA);
        trusted = LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!trusted || !system_module(trusted)) return rejected("trusted-control", GetLastError());
    }
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
    if (trusted_release) {
        if (!FreeLibrary(trusted)) return rejected("trusted-control-release", GetLastError());
        HMODULE retained = GetModuleHandleW(L"version.dll");
        if (!retained || !system_module(retained)) return rejected("system-dependency-retained-reference", ERROR_INVALID_DATA);
        puts("{\"status\":\"retained\",\"caller_reference_released\":true,\"payload_executed\":false}");
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
