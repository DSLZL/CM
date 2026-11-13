#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <bcrypt.h>
#include <userenv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#if defined(CM_DELAY_DIAGNOSTIC)
#include <delayimp.h>
#endif

#if !defined(_M_X64)
#error This bounded fixture requires native x64 MSVC
#endif

typedef struct { DWORD kind, value; char gate[48]; } Message;
typedef struct { PROCESS_INFORMATION process; HANDLE reader; } Child;
static HANDLE job, report_pipe, restricted_base;
static HANDLE socket_info_reader, socket_info_writer;
static SOCKET shared_source = INVALID_SOCKET, shared_peer = INVALID_SOCKET;
static Child children[3];
static wchar_t profile[64], executable[MAX_PATH], root[MAX_PATH];
static PSID package_sid, private_sid;
static DWORD private_sid_file_grants;
static PSID registry_sid;
static TOKEN_USER *owner;
static BOOL profile_created;
static BOOL registry_mode;
static BOOL restricted_mode;
static BOOL restricted_network;
static BOOL ordinary_restricted;
static BOOL file_controls_stage;
static BOOL restricted_code_files;
static BOOL installer_files;
static PSID installer_sid;
static BOOL file_diagnostic_done;
static const char *startup_gates[] = {
    "wsa-reg-parameters", "wsa-reg-protocol", "wsa-reg-namespace", "wsa-dll-mswsock",
    "wsa-dll-nsi", "wsa-dll-dnsapi", "wsa-dll-nlaapi", "wsa-dll-winrnr"
};
static const wchar_t *file_inputs[3];
static const wchar_t *file_aliases[] = {
    L"source-hard.txt", L"source-link.txt", L"cache-hard.txt", L"cache-link.txt", L"compiler-link.exe"
};
static DWORD file_path_checks, compiler_creation_checks;
static BOOL socket_share;
static BOOL socket_transfer;
static int socket_policy = -1;
static int peer_policy = -1;
static const wchar_t *socket_modes[] = {L"socket-ordinary", L"socket-lpac", L"socket-restricted"};
static const wchar_t *peer_modes[] = {L"peer-outside", L"peer-ordinary", L"peer-lpac", L"peer-restricted"};
static const char request[] = "GET /controlled HTTP/1.0\r\n\r\n";
static const char response[] = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK";
static const wchar_t *environment_names[] = {
    L"APPDATA", L"LOCALAPPDATA", L"SystemDrive", L"SystemRoot", L"TEMP", L"TMP", L"USERPROFILE", L"windir"
};

static void cleanup(void) {
    if (job) { CloseHandle(job); job = NULL; }
    if (restricted_base) { CloseHandle(restricted_base); restricted_base = NULL; }
    for (size_t i = 0; i < ARRAYSIZE(children); ++i) {
        if (children[i].process.hProcess) {
            if (WaitForSingleObject(children[i].process.hProcess, 5000) != WAIT_OBJECT_0) {
                TerminateProcess(children[i].process.hProcess, 2);
                WaitForSingleObject(children[i].process.hProcess, 5000);
            }
            CloseHandle(children[i].process.hProcess);
        }
        if (children[i].process.hThread) CloseHandle(children[i].process.hThread);
        if (children[i].reader) CloseHandle(children[i].reader);
    }
    if (socket_info_reader) CloseHandle(socket_info_reader);
    if (socket_info_writer) CloseHandle(socket_info_writer);
    if (shared_source != INVALID_SOCKET) closesocket(shared_source);
    if (shared_peer != INVALID_SOCKET) closesocket(shared_peer);
    if (profile_created) {
        HRESULT result = DeleteAppContainerProfile(profile);
        if (FAILED(result)) fprintf(stderr, "Owned profile cleanup failed; error=%lu\n", (DWORD)result);
    }
    if (package_sid) FreeSid(package_sid);
    if (private_sid) FreeSid(private_sid);
    LocalFree(registry_sid); registry_sid = NULL;
    LocalFree(installer_sid); installer_sid = NULL;
    free(owner);
}

static void message(DWORD kind, DWORD value, const char *gate) {
    Message item = {kind, value, {0}};
    DWORD written = 0;
    if (strcpy_s(item.gate, sizeof(item.gate), gate) != 0 ||
            !WriteFile(report_pipe, &item, (DWORD)sizeof(item), &written, NULL) || written != sizeof(item))
        ExitProcess(3);
}

static void socket_access_diagnostic(void) {
    HANDLE device = CreateFileW(L"\\\\?\\GLOBALROOT\\Device\\Afd", READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Read-only AFD device open failed; error=%lu\n", GetLastError());
        return;
    }
    PSECURITY_DESCRIPTOR descriptor = NULL;
    DWORD error = GetSecurityInfo(device, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL, &descriptor);
    CloseHandle(device);
    wchar_t *text = NULL;
    DWORD length = 0;
    if (!error && (!descriptor || !IsValidSecurityDescriptor(descriptor))) error = ERROR_INVALID_SECURITY_DESCR;
    if (!error && !ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION, &text, &length)) error = GetLastError();
    if (!error && (!text || !length || length > 8192 || wcsnlen_s(text, length) >= length))
        error = ERROR_INVALID_DATA;
    if (error) fprintf(stderr, "Read-only AFD device DACL query failed; error=%lu\n", error);
    else fprintf(stderr, "Read-only AFD device DACL; sddl=%ls\n", text);
    LocalFree(text); LocalFree(descriptor);
}

static void shared_peer_diagnostic(SOCKET socket, const char *role) {
    if (socket == INVALID_SOCKET) return;
    struct sockaddr_in peer = {0};
    int size = sizeof(peer);
    int result = getpeername(socket, (struct sockaddr *)&peer, &size);
    DWORD error = result ? (DWORD)WSAGetLastError() : 0;
    fprintf(stderr, "Read-only shared socket peer; role=%s result=%d error=%lu size=%d family=%u address=%lu port=%u\n",
        role, result, error, size, (unsigned int)peer.sin_family,
        (unsigned long)ntohl(peer.sin_addr.s_addr), (unsigned int)ntohs(peer.sin_port));
}

static __declspec(noreturn) void fail(const char *gate, DWORD error) {
    if (report_pipe) message(2, error, gate);
    else {
        fprintf(stderr, "LPAC mechanism failed at %s; error=%lu\n", gate, error);
        if (installer_files && file_diagnostic_done)
            fprintf(stderr, "Actual file controls completed before startup: outside_baselines=6/3; "
                "restricted_checks=6/3; denied_error=5; compiler_executed=false\n");
        if (restricted_network && !strcmp(gate, "provider-socket") && error == WSAEACCES)
            socket_access_diagnostic();
        if (socket_share) {
            shared_peer_diagnostic(shared_source, "parent-retained");
            shared_peer_diagnostic(shared_peer, "parent-shared");
        }
        cleanup();
    }
    ExitProcess(2);
}

#if defined(CM_DELAY_DIAGNOSTIC)
static FARPROC WINAPI delay_failure(unsigned reason, PDelayLoadInfo info) {
    char gate[48];
    if (!info || !info->szDll || (reason != dliFailLoadLib && reason != dliFailGetProc) ||
            _snprintf_s(gate, sizeof(gate), _TRUNCATE, "%s-%s",
                reason == dliFailLoadLib ? "dll-load" : "dll-import", info->szDll) < 0)
        fail("delay-diagnostic", ERROR_INVALID_DATA);
    fail(gate, info->dwLastError);
}

const PfnDliHook __pfnDliFailureHook2 = delay_failure;

static void check_delayed_imports(void) {
    const char *names[] = {"bcrypt.dll", "USERENV.dll", "ADVAPI32.dll", "WS2_32.dll",
        "api-ms-win-security-base-l1-2-2.dll"};
    for (size_t i = 0; i < ARRAYSIZE(names); ++i) {
        HRESULT result = __HrLoadAllImportsForDll(names[i]);
        if (FAILED(result)) fail("delay-preload", (DWORD)result);
    }
}
#endif

static void startup_diagnostics(BOOL outside) {
    const wchar_t *keys[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters",
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9",
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5"
    };
    const wchar_t *libraries[] = {L"mswsock.dll", L"nsi.dll", L"dnsapi.dll", L"nlaapi.dll", L"winrnr.dll"};
    for (size_t i = 0; i < ARRAYSIZE(keys); ++i) {
        HKEY key = NULL;
        LSTATUS error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keys[i], 0,
            outside ? KEY_READ : KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &key);
        if (outside) {
            PSECURITY_DESCRIPTOR descriptor = NULL;
            wchar_t *text = NULL;
            DWORD length = 0, query_error = (DWORD)error;
            if (!query_error) query_error = GetSecurityInfo(key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
                NULL, NULL, NULL, NULL, &descriptor);
            if (!query_error && (!descriptor || !IsValidSecurityDescriptor(descriptor)))
                query_error = ERROR_INVALID_SECURITY_DESCR;
            if (!query_error && !ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION, &text, &length)) query_error = GetLastError();
            if (!query_error && (!text || !length || length > 8192 || wcsnlen_s(text, length) >= length))
                query_error = ERROR_INVALID_DATA;
            if (query_error) fprintf(stderr, "Outside registry DACL: %s; error=%lu\n", startup_gates[i], query_error);
            else fprintf(stderr, "Outside registry DACL: %s; sddl=%ls\n", startup_gates[i], text);
            LocalFree(text); LocalFree(descriptor);
        }
        if (key && RegCloseKey(key)) fail("wsa-diagnostic-key-close", ERROR_INVALID_HANDLE);
        if (!outside) message(11, (DWORD)error, startup_gates[i]);
    }
    if (outside) return;
    for (size_t i = 0; i < ARRAYSIZE(libraries); ++i) {
        HMODULE library = LoadLibraryExW(libraries[i], NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        DWORD error = library ? ERROR_SUCCESS : GetLastError();
        if (library && !FreeLibrary(library)) fail("wsa-diagnostic-dll-close", GetLastError());
        message(11, error, startup_gates[ARRAYSIZE(keys) + i]);
    }
}

static void *token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD size = 0;
    GetTokenInformation(token, kind, NULL, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !size || size > 65536)
        fail("token-size", GetLastError());
    void *data = malloc(size);
    if (!data) fail("token-memory", ERROR_OUTOFMEMORY);
    if (!GetTokenInformation(token, kind, data, size, &size)) fail("token-query", GetLastError());
    return data;
}

static void fail_restriction(const char *role, const char *operation, DWORD error) {
    char gate[48];
    if (_snprintf_s(gate, sizeof(gate), _TRUNCATE, "%s-restrict-%s", role, operation) < 0)
        fail("restricted-diagnostic-bound", ERROR_INVALID_DATA);
    fail(gate, error);
}

static void inspect_restrictions(HANDLE token, const char *role) {
    TOKEN_GROUPS *sids = token_info(token, TokenRestrictedSids);
    TOKEN_PRIVILEGES *privileges = token_info(token, TokenPrivileges);
    TOKEN_USER *user = token_info(token, TokenUser);
    TOKEN_DEFAULT_DACL *defaults = token_info(token, TokenDefaultDacl);
    BOOL seen[3] = {0};
    BOOL private_default = FALSE;
    LUID traverse;
    if (sids->GroupCount != 3 || !EqualSid(user->User.Sid, owner->User.Sid))
        fail_restriction(role, "identity-or-count", ERROR_INVALID_DATA);
    for (DWORD i = 0; i < sids->GroupCount; ++i) {
        PSID sid = sids->Groups[i].Sid;
        int index = IsWellKnownSid(sid, WinWorldSid) ? 0 :
            (installer_files ? EqualSid(sid, installer_sid) :
                IsWellKnownSid(sid, restricted_code_files ? WinRestrictedCodeSid : WinBuiltinUsersSid)) ? 1 :
            EqualSid(sid, private_sid) ? 2 : -1;
        if (index < 0 || seen[index] || (sids->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
            fail_restriction(role, "sid-policy", ERROR_INVALID_DATA);
        seen[index] = TRUE;
    }
    if (installer_files) {
        TOKEN_GROUPS *groups = token_info(token, TokenGroups);
        for (DWORD i = 0; i < groups->GroupCount; ++i)
            if (EqualSid(groups->Groups[i].Sid, installer_sid))
                fail_restriction(role, "system-sid-normal-group", ERROR_INVALID_DATA);
        free(groups);
    }
    if (!LookupPrivilegeValueW(NULL, L"SeChangeNotifyPrivilege", &traverse))
        fail_restriction(role, "privilege-name", GetLastError());
    for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
        LUID_AND_ATTRIBUTES item = privileges->Privileges[i];
        if ((item.Attributes & SE_PRIVILEGE_ENABLED) &&
                (item.Luid.LowPart != traverse.LowPart || item.Luid.HighPart != traverse.HighPart))
            fail_restriction(role, "enabled-privilege", ERROR_INVALID_DATA);
    }
    if (!defaults->DefaultDacl || !IsValidAcl(defaults->DefaultDacl))
        fail_restriction(role, "default-dacl", ERROR_INVALID_ACL);
    for (DWORD i = 0; i < defaults->DefaultDacl->AceCount; ++i) {
        void *item = NULL;
        if (!GetAce(defaults->DefaultDacl, i, &item))
            fail_restriction(role, "default-dacl-query", GetLastError());
        ACCESS_ALLOWED_ACE *ace = item;
        if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && EqualSid(&ace->SidStart, private_sid)) {
            if (private_default || ace->Mask != GENERIC_ALL || ace->Header.AceFlags)
                fail_restriction(role, "default-dacl-policy", ERROR_INVALID_ACL);
            private_default = TRUE;
        }
    }
    if (!private_default) fail_restriction(role, "default-dacl-private", ERROR_INVALID_ACL);
    free(sids); free(privileges); free(user); free(defaults);
}

static void prepare_restricted_token(void) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &token))
        fail("restricted-source-token", GetLastError());
    TOKEN_GROUPS *existing = token_info(token, TokenRestrictedSids);
    if (existing->GroupCount) fail("restricted-source-intersection", ERROR_INVALID_DATA);
    free(existing);
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    DWORD random[4];
    if (BCryptGenRandom(NULL, (PUCHAR)random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG))
        fail("private-sid-random", ERROR_GEN_FAILURE);
    // Keep the file restriction identity separate from the AppContainer package namespace.
    if (!AllocateAndInitializeSid(&authority, 5, SECURITY_NT_NON_UNIQUE,
            random[0], random[1], random[2], random[3], 0, 0, 0, &private_sid))
        fail("private-sid-create", GetLastError());
    if (!IsValidSid(private_sid) || EqualSid(private_sid, owner->User.Sid))
        fail("private-sid-identity", ERROR_INVALID_SID);
    TOKEN_GROUPS *groups = token_info(token, TokenGroups);
    for (DWORD i = 0; i < groups->GroupCount; ++i)
        if (EqualSid(private_sid, groups->Groups[i].Sid)) fail("private-sid-source-group", ERROR_INVALID_DATA);
    free(groups);
    BYTE world[SECURITY_MAX_SID_SIZE], system_sid[SECURITY_MAX_SID_SIZE];
    DWORD world_size = sizeof(world), system_size = sizeof(system_sid);
    if (installer_files && !ConvertStringSidToSidW(
            L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &installer_sid))
        fail("installer-restricting-sid", GetLastError());
    if (!CreateWellKnownSid(WinWorldSid, NULL, world, &world_size) ||
            !CreateWellKnownSid(restricted_code_files ? WinRestrictedCodeSid : WinBuiltinUsersSid,
                NULL, system_sid, &system_size))
        fail("restricted-well-known-sids", GetLastError());
    SID_AND_ATTRIBUTES sids[3] = {{world, 0}, {installer_files ? installer_sid : system_sid, 0}, {private_sid, 0}};
    for (DWORD i = 0; i < ARRAYSIZE(sids); ++i)
        if (!IsValidSid(sids[i].Sid)) fail("restricted-input-sid", ERROR_INVALID_SID);
    if (!CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 3, sids, &restricted_base)) {
        DWORD creation_error = GetLastError();
        fprintf(stderr, "Restricted-token inputs: valid_sids=3; attributes=0; flags=%lu\n", (DWORD)DISABLE_MAX_PRIVILEGE);
        // Failure-only controls isolate SID compatibility without running a weaker token.
        for (DWORD i = 0; i < 2; ++i) {
            HANDLE diagnostic = NULL;
            BOOL created = CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL,
                i ? 1 : 2, sids + (i ? 2 : 0), &diagnostic);
            DWORD error = created ? ERROR_SUCCESS : GetLastError();
            if (created && !diagnostic) fail("restricted-diagnostic-handle", ERROR_INVALID_HANDLE);
            if (diagnostic && !CloseHandle(diagnostic)) fail("restricted-diagnostic-close", GetLastError());
            fprintf(stderr, "Restricted-token diagnostic: policy=%s; created=%s; error=%lu; handle=%s\n",
                i ? "private-nt" : installer_files ? "world-trusted-installer" :
                    restricted_code_files ? "world-restricted-code" : "world-users",
                created ? "true" : "false", error,
                diagnostic ? "closed" : "not-created");
        }
        CloseHandle(token);
        fail("restricted-token-create", creation_error);
    }
    CloseHandle(token);
    TOKEN_DEFAULT_DACL *defaults = token_info(restricted_base, TokenDefaultDacl);
    if (!defaults->DefaultDacl || !IsValidAcl(defaults->DefaultDacl)) fail("base-default-dacl", ERROR_INVALID_ACL);
    EXPLICIT_ACCESSW entry = {0};
    PACL acl = NULL;
    entry.grfAccessPermissions = GENERIC_ALL;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.ptstrName = (LPWSTR)private_sid;
    DWORD error = SetEntriesInAclW(1, &entry, defaults->DefaultDacl, &acl);
    if (error) fail("base-default-dacl-build", error);
    TOKEN_DEFAULT_DACL updated = {acl};
    BOOL applied = SetTokenInformation(restricted_base, TokenDefaultDacl, &updated, sizeof(updated));
    error = applied ? ERROR_SUCCESS : GetLastError();
    LocalFree(acl); free(defaults);
    if (error) fail("base-default-dacl-set", error);
    inspect_restrictions(restricted_base, "base");
}

static void derive_registry_capability(void) {
    PSID *groups = NULL, *capabilities = NULL;
    DWORD group_count = 0, count = 0;
    BOOL derived = DeriveCapabilitySidsFromName(L"registryRead", &groups, &group_count, &capabilities, &count);
    DWORD error = derived ? ERROR_INVALID_DATA : GetLastError();
    if (derived && capabilities && count == 1 && IsValidSid(capabilities[0])) {
        registry_sid = capabilities[0];
        capabilities[0] = NULL;
    }
    if (groups) {
        for (DWORD i = 0; i < group_count; ++i) LocalFree(groups[i]);
        LocalFree(groups);
    }
    if (capabilities) {
        for (DWORD i = 0; i < count; ++i) LocalFree(capabilities[i]);
        LocalFree(capabilities);
    }
    if (!registry_sid) fail("derive-registry-read", error);
}

static LSTATUS open_host_environment(REGSAM access) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) fail("registry-user-token", GetLastError());
    TOKEN_USER *user = token_info(token, TokenUser);
    LPWSTR sid = NULL;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid)) fail("registry-user-sid", GetLastError());
    wchar_t path[256];
    if (_snwprintf_s(path, ARRAYSIZE(path), _TRUNCATE, L"%ls\\Environment", sid) < 0)
        fail("registry-key-path", ERROR_INVALID_DATA);
    LocalFree(sid); free(user); CloseHandle(token);
    HKEY key = NULL;
    LSTATUS result = RegOpenKeyExW(HKEY_USERS, path, 0, access, &key);
    if (result == ERROR_SUCCESS) {
        LSTATUS closed = RegCloseKey(key);
        if (closed != ERROR_SUCCESS) fail("registry-key-close", (DWORD)closed);
    }
    return result;
}

static void check_child_environment(void) {
    BOOL seen[ARRAYSIZE(environment_names)] = {0};
    LPWCH block = GetEnvironmentStringsW();
    if (!block) fail("child-env-read", GetLastError());
    for (LPWCH entry = block; *entry; entry += wcslen(entry) + 1) {
        const wchar_t *separator = wcschr(entry, L'=');
        BOOL found = FALSE;
        for (size_t i = 0; separator && i < ARRAYSIZE(environment_names); ++i) {
            size_t size = wcslen(environment_names[i]);
            if ((size_t)(separator - entry) == size && !_wcsnicmp(entry, environment_names[i], size)) {
                if (seen[i] || !separator[1]) fail("child-env-duplicate-or-empty", ERROR_INVALID_DATA);
                seen[i] = found = TRUE;
                break;
            }
        }
        if (!found) fail("child-env-unexpected-name", ERROR_INVALID_DATA);
    }
    FreeEnvironmentStringsW(block);
    for (size_t i = 0; i < ARRAYSIZE(seen); ++i)
        if (!seen[i]) fail("child-env-missing-name", ERROR_ENVVAR_NOT_FOUND);
}

static void private_acl(wchar_t *path, PSID allowed, DWORD access) {
    EXPLICIT_ACCESSW entries[3] = {0};
    BOOL private_grant = restricted_mode && EqualSid(allowed, package_sid);
    PACL acl = NULL;
    for (size_t i = 0; i < ARRAYSIZE(entries); ++i) {
        entries[i].grfAccessMode = GRANT_ACCESS;
        entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    }
    entries[0].grfAccessPermissions = FILE_ALL_ACCESS;
    entries[0].Trustee.ptstrName = (LPWSTR)owner->User.Sid;
    entries[1].grfAccessPermissions = access;
    entries[1].Trustee.ptstrName = (LPWSTR)allowed;
    if (private_grant) {
        entries[2].grfAccessPermissions = access;
        entries[2].Trustee.ptstrName = (LPWSTR)private_sid;
    }
    DWORD error = SetEntriesInAclW(private_grant ? 3 : 2, entries, NULL, &acl);
    if (error) fail("owned-acl-build", error);
    error = SetNamedSecurityInfoW(path, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL);
    LocalFree(acl);
    if (error) fail("owned-acl-set", error);
    if (private_grant) ++private_sid_file_grants;
}

static void path_for(wchar_t *out, const wchar_t *name) {
    if (_snwprintf_s(out, MAX_PATH, _TRUNCATE, L"%ls\\%ls", root, name) < 0)
        fail("owned-path", ERROR_FILENAME_EXCED_RANGE);
}

static DWORD read_marker(const wchar_t *name) {
    wchar_t path[MAX_PATH];
    char value = 0;
    DWORD size = 0;
    path_for(path, name);
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return GetLastError();
    BOOL okay = ReadFile(file, &value, 1, &size, NULL);
    DWORD error = !okay ? GetLastError() : size == 1 && value == 'K' ? ERROR_SUCCESS : ERROR_INVALID_DATA;
    CloseHandle(file);
    return error;
}

static void create_marker(const wchar_t *name, PSID allowed) {
    wchar_t path[MAX_PATH];
    DWORD written = 0;
    path_for(path, name);
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) fail("owned-create", GetLastError());
    BOOL okay = WriteFile(file, "K", 1, &written, NULL);
    DWORD error = okay ? ERROR_INVALID_DATA : GetLastError();
    CloseHandle(file);
    if (!okay || written != 1) fail("owned-write", error);
    private_acl(path, allowed, FILE_GENERIC_READ);
}

static DWORD read_path_error(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return GetLastError();
    char byte = 0;
    DWORD size = 0;
    BOOL read = ReadFile(file, &byte, 1, &size, NULL);
    DWORD error = read ? size == 1 ? ERROR_SUCCESS : ERROR_INVALID_DATA : GetLastError();
    if (!CloseHandle(file)) fail("file-control-close", GetLastError());
    return error;
}

static DWORD compiler_creation_error(const wchar_t *path, BOOL search) {
    STARTUPINFOW startup = {sizeof(startup)};
    PROCESS_INFORMATION process = {0};
    wchar_t command[MAX_PATH + 16];
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE, L"\"%ls\" /?", path) < 0)
        fail("compiler-command-bound", ERROR_INVALID_DATA);
    // Never execute an unexpectedly permitted compiler.
    if (!CreateProcessW(search ? NULL : path, command, NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, root, &startup, &process)) return GetLastError();
    if (job && !AssignProcessToJobObject(job, process.hProcess)) fail("compiler-baseline-job", GetLastError());
    if (!TerminateProcess(process.hProcess, 0)) fail("compiler-control-terminate", GetLastError());
    DWORD wait = WaitForSingleObject(process.hProcess, 5000);
    if (wait != WAIT_OBJECT_0) fail("compiler-control-wait", wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError());
    if (!CloseHandle(process.hThread) || !CloseHandle(process.hProcess))
        fail("compiler-control-close", GetLastError());
    return ERROR_SUCCESS;
}

static void check_file_controls(BOOL denied) {
    DWORD expected = denied ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    const char *methods[] = {"absolute", "hardlink", "symlink"};
    for (size_t input = 0; input < 2; ++input) {
        for (size_t method = 0; method < 3; ++method) {
            wchar_t alias[MAX_PATH];
            if (method) path_for(alias, file_aliases[input * 2 + method - 1]);
            DWORD error = read_path_error(method ? alias : file_inputs[input]);
            if (error != expected) {
                char gate[48];
                if (_snprintf_s(gate, sizeof(gate), _TRUNCATE, "%s-%s-%s", denied ? "client" : "outside",
                        input ? "cache" : "source", methods[method]) < 0) fail("file-gate-bound", ERROR_INVALID_DATA);
                fail(gate, error);
            }
            ++file_path_checks;
        }
    }
    wchar_t directory[MAX_PATH], alias[MAX_PATH], previous[32768];
    if (wcscpy_s(directory, ARRAYSIZE(directory), file_inputs[2])) fail("compiler-directory", ERROR_INVALID_DATA);
    wchar_t *name = wcsrchr(directory, L'\\');
    if (!name) fail("compiler-directory", ERROR_INVALID_DATA);
    *name++ = L'\0';
    SetLastError(ERROR_SUCCESS);
    DWORD length = GetEnvironmentVariableW(L"PATH", previous, ARRAYSIZE(previous));
    DWORD path_error = length ? ERROR_SUCCESS : GetLastError();
    if (length >= ARRAYSIZE(previous) || (!length && path_error != ERROR_ENVVAR_NOT_FOUND && path_error != ERROR_SUCCESS))
        fail("compiler-path-baseline", path_error);
    if (!SetEnvironmentVariableW(L"PATH", directory)) fail("compiler-path-set", GetLastError());
    for (size_t method = 0; method < 3; ++method) {
        path_for(alias, file_aliases[4]);
        DWORD error = compiler_creation_error(method == 0 ? file_inputs[2] : method == 1 ? name : alias, method == 1);
        if (error != expected) {
            char gate[48];
            if (_snprintf_s(gate, sizeof(gate), _TRUNCATE, "%s-compiler-%s", denied ? "client" : "outside",
                    method == 0 ? "absolute" : method == 1 ? "PATH" : "symlink") < 0)
                fail("compiler-gate-bound", ERROR_INVALID_DATA);
            fail(gate, error);
        }
        ++compiler_creation_checks;
    }
    if (!SetEnvironmentVariableW(L"PATH", length ? previous : NULL)) fail("compiler-path-restore", GetLastError());
}

static void prepare_file_controls(void) {
    for (size_t i = 0; i < ARRAYSIZE(file_aliases); ++i) {
        wchar_t path[MAX_PATH];
        path_for(path, file_aliases[i]);
        const wchar_t *target = file_inputs[i < 4 ? i / 2 : 2];
        BOOL created = i < 4 && !(i % 2) ? CreateHardLinkW(path, target, NULL) :
            CreateSymbolicLinkW(path, target, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
        if (!created) fail("outside-file-alias-create", GetLastError());
    }
    check_file_controls(FALSE);
    if (file_path_checks != 6 || compiler_creation_checks != 3) fail("outside-file-control-count", ERROR_INVALID_DATA);
}

static SOCKET listener(unsigned short *port, BOOL provider) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) fail(provider ? "provider-socket" : "outside-socket", (DWORD)WSAGetLastError());
    struct sockaddr_in address = {0};
    int size = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(sock, (const struct sockaddr *)&address, sizeof(address)))
        fail(provider ? "provider-bind" : "outside-bind", (DWORD)WSAGetLastError());
    if (listen(sock, 2)) fail(provider ? "provider-listen" : "outside-listen", (DWORD)WSAGetLastError());
    if (getsockname(sock, (struct sockaddr *)&address, &size))
        fail(provider ? "provider-address" : "outside-address", (DWORD)WSAGetLastError());
    *port = ntohs(address.sin_port);
    return sock;
}

static int connect_bounded(SOCKET sock, unsigned short port) {
    u_long mode = 1;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    if (ioctlsocket(sock, FIONBIO, &mode)) return WSAGetLastError();
    int result = connect(sock, (const struct sockaddr *)&address, sizeof(address));
    int error = result ? WSAGetLastError() : 0;
    if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) {
        fd_set writable, exceptional;
        struct timeval timeout = {3, 0};
        FD_ZERO(&writable); FD_SET(sock, &writable);
        FD_ZERO(&exceptional); FD_SET(sock, &exceptional);
        result = select(0, NULL, &writable, &exceptional, &timeout);
        if (result <= 0) return result ? WSAGetLastError() : WSAETIMEDOUT;
        int length = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&error, &length)) return WSAGetLastError();
    }
    mode = 0;
    if (!error && ioctlsocket(sock, FIONBIO, &mode)) return WSAGetLastError();
    DWORD timeout = 3000;
    if (!error && (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout))))
        return WSAGetLastError();
    return error;
}

static void exchange(SOCKET sock, const char *sent, size_t sent_size, const char *expected, size_t size) {
    size_t offset = 0;
    char buffer[128];
    if (size > sizeof(buffer)) fail("http-bound", ERROR_INVALID_DATA);
    while (offset < sent_size) {
        int count = send(sock, sent + offset, (int)(sent_size - offset), 0);
        if (count <= 0) fail("http-send", (DWORD)WSAGetLastError());
        offset += (size_t)count;
    }
    offset = 0;
    while (offset < size) {
        int count = recv(sock, buffer + offset, (int)(size - offset), 0);
        if (count <= 0) fail("http-recv", (DWORD)WSAGetLastError());
        offset += (size_t)count;
    }
    if (memcmp(buffer, expected, size)) fail("http-response", ERROR_INVALID_DATA);
}

static void inspect(Child *child, BOOL lpac, const wchar_t *role) {
    HANDLE token = NULL;
    BOOL member = FALSE;
    if (!OpenProcessToken(child->process.hProcess, TOKEN_QUERY, &token)) fail("child-token", GetLastError());
    DWORD *container = token_info(token, TokenIsAppContainer);
    if (peer_policy == 0) {
        TOKEN_USER *outside_user = token_info(token, TokenUser);
        if (*container || !EqualSid(outside_user->User.Sid, owner->User.Sid) ||
                !IsProcessInJob(child->process.hProcess, job, &member) || !member)
            fail("outside-shared-peer-token", ERROR_INVALID_DATA);
        free(container); free(outside_user); CloseHandle(token);
        return;
    }
    TOKEN_APPCONTAINER_INFORMATION *identity = token_info(token, TokenAppContainerSid);
    TOKEN_GROUPS *capabilities = token_info(token, TokenCapabilities);
    TOKEN_USER *user = token_info(token, TokenUser);
    TOKEN_MANDATORY_LABEL *integrity = token_info(token, TokenIntegrityLevel);
    DWORD level = *GetSidSubAuthority(integrity->Label.Sid,
        (DWORD)(*GetSidSubAuthorityCount(integrity->Label.Sid) - 1));
    if (*container != 1 || !identity->TokenAppContainer || !EqualSid(identity->TokenAppContainer, package_sid) ||
            capabilities->GroupCount != (DWORD)(lpac && registry_mode ? 1 : 0) ||
            !EqualSid(user->User.Sid, owner->User.Sid) || level != SECURITY_MANDATORY_LOW_RID ||
            !IsProcessInJob(child->process.hProcess, job, &member) || !member)
        fail("outside-token-or-job", ERROR_INVALID_DATA);
    if (lpac && registry_mode && (!EqualSid(capabilities->Groups[0].Sid, registry_sid) ||
            !(capabilities->Groups[0].Attributes & SE_GROUP_ENABLED) ||
            (capabilities->Groups[0].Attributes & SE_GROUP_USE_FOR_DENY_ONLY)))
        fail("outside-registry-capability", ERROR_INVALID_DATA);
    if (restricted_mode && (lpac || (ordinary_restricted && wcscmp(role, L"control"))))
        inspect_restrictions(token, socket_share ? "socket-share" :
            socket_policy >= 0 ? "socket" : !wcscmp(role, L"provider") ? "provider" : "client");
    free(container); free(identity); free(capabilities); free(user); free(integrity);
    CloseHandle(token);
}

static Child *spawn(size_t index, const wchar_t *role, BOOL lpac, unsigned short provider, unsigned short canary) {
    Child *child = &children[index];
    HANDLE writer = NULL;
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    SECURITY_CAPABILITIES capabilities = {0};
    SID_AND_ATTRIBUTES registry = {registry_sid, SE_GROUP_ENABLED};
    STARTUPINFOEXW startup = {0};
    SIZE_T size = 0;
    DWORD policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    wchar_t command[2048], environment[4096];
    if (!CreatePipe(&child->reader, &writer, &security, 0) ||
            !SetHandleInformation(child->reader, HANDLE_FLAG_INHERIT, 0)) fail("report-pipe", GetLastError());
    size_t used = 0;
    for (size_t i = 0; i < ARRAYSIZE(environment_names); ++i) {
        if (ARRAYSIZE(environment) - used <= wcslen(environment_names[i]) + 2)
            fail("child-env-name-bound", ERROR_INSUFFICIENT_BUFFER);
        int count = swprintf_s(environment + used, ARRAYSIZE(environment) - used, L"%ls=", environment_names[i]);
        if (count < 0) fail("child-env-name-bound", ERROR_INVALID_DATA);
        used += (size_t)count;
        DWORD space = (DWORD)(ARRAYSIZE(environment) - used - 1);
        if (!space) fail("child-env-value-bound", ERROR_INVALID_DATA);
        // AppContainer creation redirects profile/temp variables; never inherit the runner's full environment.
        DWORD length = (!wcscmp(environment_names[i], L"SystemRoot") || !wcscmp(environment_names[i], L"windir")) ?
            GetWindowsDirectoryW(environment + used, space) :
            GetEnvironmentVariableW(environment_names[i], environment + used, space);
        if (!length || length >= space) fail("child-env-value", length ? ERROR_INSUFFICIENT_BUFFER : GetLastError());
        used += (size_t)length + 1;
    }
    environment[used] = L'\0';
    const wchar_t *mode = installer_files ? L"restricted-installer-appcontainer-files" :
        restricted_code_files ? L"restricted-code-appcontainer-files" :
        file_controls_stage ? L"restricted-appcontainer-files" :
        ordinary_restricted ? L"restricted-appcontainer-network" :
        peer_policy >= 0 ? peer_modes[peer_policy] : socket_transfer ? L"shared-transfer" :
        socket_share ? L"socket-share" : socket_policy >= 0 ? socket_modes[socket_policy] :
        restricted_network ? L"restricted-network" : restricted_mode ? L"registry-restricted" :
            registry_mode ? L"registry-read" : L"";
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE, L"\"%ls\" %ls %llu %u %u%ls%ls", executable, role,
            (unsigned long long)(UINT_PTR)writer, (unsigned int)provider, (unsigned int)canary,
            *mode ? L" " : L"", mode) < 0)
        fail("child-command", ERROR_INVALID_DATA);
    if (socket_share) {
        size_t used_command = wcslen(command);
        if (!socket_info_reader || _snwprintf_s(command + used_command, ARRAYSIZE(command) - used_command,
                _TRUNCATE, L" %llu", (unsigned long long)(UINT_PTR)socket_info_reader) < 0)
            fail("socket-share-command", ERROR_INVALID_DATA);
    }
    if (file_controls_stage) {
        for (size_t i = 0; i < ARRAYSIZE(file_inputs); ++i) {
            size_t used_command = wcslen(command);
            if (_snwprintf_s(command + used_command, ARRAYSIZE(command) - used_command,
                    _TRUNCATE, L" \"%ls\"", file_inputs[i]) < 0) fail("file-child-command-bound", ERROR_INVALID_DATA);
        }
    }
    DWORD attributes = peer_policy == 0 ? 1 : lpac ? 3 : 2;
    InitializeProcThreadAttributeList(NULL, attributes, 0, &size);
    startup.lpAttributeList = malloc(size);
    if (!startup.lpAttributeList || !InitializeProcThreadAttributeList(startup.lpAttributeList, attributes, 0, &size))
        fail("child-attributes", GetLastError());
    capabilities.AppContainerSid = package_sid;
    if (lpac && registry_mode) {
        capabilities.Capabilities = &registry;
        capabilities.CapabilityCount = 1;
    }
    HANDLE inherited[] = {writer, socket_info_reader};
    if ((peer_policy != 0 && !UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities, sizeof(capabilities), NULL, NULL)) ||
            !UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, socket_share ? sizeof(inherited) : sizeof(writer), NULL, NULL) ||
            (lpac && !UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &policy, sizeof(policy), NULL, NULL)))
        fail("child-attribute-update", GetLastError());
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
    BOOL restricted_child = restricted_mode && (lpac || (ordinary_restricted && wcscmp(role, L"control")));
    BOOL created = restricted_child ?
        CreateProcessAsUserW(restricted_base, executable, command, NULL, NULL, TRUE, flags,
            environment, root, &startup.StartupInfo, &child->process) :
        CreateProcessW(executable, command, NULL, NULL, TRUE, flags,
            environment, root, &startup.StartupInfo, &child->process);
    if (!created) fail(restricted_child ?
        (socket_share ? "socket-share-restricted-create" : socket_policy >= 0 ? "socket-restricted-create" :
            !wcscmp(role, L"provider") ? "provider-restricted-create" : "client-restricted-create") :
        "child-create", GetLastError());
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    CloseHandle(writer);
    if (!AssignProcessToJobObject(job, child->process.hProcess)) fail("child-job", GetLastError());
    inspect(child, lpac, role);
    if (ResumeThread(child->process.hThread) == (DWORD)-1) fail("child-resume", GetLastError());
    CloseHandle(child->process.hThread); child->process.hThread = NULL;
    return child;
}

static DWORD receive(Child *child, DWORD kind) {
    BOOL seen[ARRAYSIZE(startup_gates)] = {0};
    for (;;) {
        Message item = {0};
        DWORD size = 0;
        if (!ReadFile(child->reader, &item, (DWORD)sizeof(item), &size, NULL)) fail("child-report", GetLastError());
        if (size != sizeof(item) || !memchr(item.gate, 0, sizeof(item.gate)))
            fail("child-report-bytes", ERROR_INVALID_DATA);
        if (installer_files && item.kind == 11) {
            size_t index = 0;
            while (index < ARRAYSIZE(startup_gates) && strcmp(item.gate, startup_gates[index])) ++index;
            if (index == ARRAYSIZE(startup_gates) || seen[index]) fail("startup-diagnostic-kind", ERROR_INVALID_DATA);
            seen[index] = TRUE;
            fprintf(stderr, "Winsock startup diagnostic: %s; result=%lu\n", item.gate, item.value);
            continue;
        }
        if (item.kind == 2) fail(item.gate, item.value);
        if (item.kind != kind || strcmp(item.gate, kind == 1 ? "internal-provider-ready" :
                kind == 4 ? "socket-observation" : kind == 5 ? "shared-socket-ready" :
                kind == 6 ? "shared-peer-address" : kind == 7 ? "shared-peer-port" :
                kind == 8 ? "outside-connect-observed" : kind == 9 ? "file-path-checks" :
                kind == 10 ? "compiler-creation-checks" : "complete"))
            fail("child-report-kind", ERROR_INVALID_DATA);
        return item.value;
    }
}

static void finished(Child *child) {
    DWORD code = 0;
    DWORD wait = WaitForSingleObject(child->process.hProcess, 30000);
    if (wait != WAIT_OBJECT_0) fail("child-exit-wait", wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError());
    if (!GetExitCodeProcess(child->process.hProcess, &code)) fail("child-exit-code", GetLastError());
    if (code) {
        fprintf(stderr, "Native child role=%s; exit=%lu; hex=0x%08lX\n",
            socket_share ? "socket-share" : socket_policy >= 0 ? "socket" : child == &children[0] ? "control" :
                child == &children[1] ? "provider" : "client", code, code);
        if (code == 2) receive(child, 3);
        fail("child-exit", code);
    }
    if (receive(child, 3)) fail("child-result", ERROR_INVALID_DATA);
    CloseHandle(child->process.hProcess); child->process.hProcess = NULL;
    CloseHandle(child->reader); child->reader = NULL;
}

int wmain(int argc, wchar_t **argv) {
    DWORD length = GetModuleFileNameW(NULL, executable, ARRAYSIZE(executable));
    if (!length || length >= ARRAYSIZE(executable)) fail("executable-path", GetLastError());
    if (wcscpy_s(root, ARRAYSIZE(root), executable)) fail("root-path", ERROR_INVALID_DATA);
    wchar_t *separator = wcsrchr(root, L'\\');
    if (!separator) fail("root-path", ERROR_INVALID_DATA);
    *separator = L'\0';
    const wchar_t *mode = argc == 6 || argc == 7 || argc == 9 ? argv[5] : argc >= 2 ? argv[1] : NULL;
    restricted_code_files = mode && !wcscmp(mode, L"restricted-code-appcontainer-files");
    installer_files = mode && !wcscmp(mode, L"restricted-installer-appcontainer-files");
    file_controls_stage = installer_files || restricted_code_files || (mode && !wcscmp(mode, L"restricted-appcontainer-files"));
    BOOL file_parent = file_controls_stage && argc == 5;
    if (file_controls_stage) {
        if (!file_parent && argc != 9) fail("file-control-arguments", ERROR_INVALID_PARAMETER);
        for (size_t i = 0; i < ARRAYSIZE(file_inputs); ++i) {
            const wchar_t *path = argv[(file_parent ? 2 : 6) + i];
            if (wcslen(path) < 4 || wcslen(path) >= MAX_PATH || path[1] != L':' || path[2] != L'\\' || wcschr(path, L'"'))
                fail("file-control-input-path", ERROR_INVALID_PARAMETER);
            file_inputs[i] = path;
        }
    } else if (argc == 9) fail("file-control-arguments", ERROR_INVALID_PARAMETER);
    ordinary_restricted = file_controls_stage || (mode && !wcscmp(mode, L"restricted-appcontainer-network"));
    socket_transfer = mode && !wcscmp(mode, L"shared-transfer");
    socket_share = socket_transfer || (mode && !wcscmp(mode, L"socket-share"));
    for (size_t i = 0; mode && i < ARRAYSIZE(socket_modes); ++i)
        if (!wcscmp(mode, socket_modes[i])) socket_policy = (int)i;
    for (size_t i = 0; mode && i < ARRAYSIZE(peer_modes); ++i)
        if (!wcscmp(mode, peer_modes[i])) { peer_policy = (int)i; socket_share = TRUE; }
    if (!file_parent && (argc == 5 || argc == 6 || argc == 7 || argc == 9)) {
        if ((argc == 7) != socket_share) fail("socket-share-arguments", ERROR_INVALID_PARAMETER);
        if (argc >= 6) {
            if (wcscmp(argv[5], L"registry-read") && wcscmp(argv[5], L"registry-restricted") &&
                    wcscmp(argv[5], L"restricted-network") && !ordinary_restricted && socket_policy < 0 && !socket_share)
                fail("child-mode", ERROR_INVALID_PARAMETER);
            registry_mode = TRUE;
            restricted_network = !file_controls_stage && (ordinary_restricted || !wcscmp(argv[5], L"restricted-network"));
            restricted_mode = ordinary_restricted || (socket_share && peer_policy < 0) || peer_policy == 3 ||
                socket_policy == 2 || restricted_network || !wcscmp(argv[5], L"registry-restricted");
        }
        wchar_t *end = NULL;
        report_pipe = (HANDLE)(UINT_PTR)wcstoull(argv[2], &end, 10);
        if (!report_pipe || !end || *end) fail("report-argument", ERROR_INVALID_DATA);
        if (socket_share) {
            if (wcscmp(argv[1], L"socket-share") || wcscmp(argv[3], L"0") || wcscmp(argv[4], L"0") ||
                    !*argv[6] || wcslen(argv[6]) > 20 || wcsspn(argv[6], L"0123456789") != wcslen(argv[6]))
                fail("socket-share-arguments", ERROR_INVALID_PARAMETER);
            socket_info_reader = (HANDLE)(UINT_PTR)wcstoull(argv[6], &end, 10);
            if (!socket_info_reader || socket_info_reader == INVALID_HANDLE_VALUE || !end || *end)
                fail("socket-share-input-handle", ERROR_INVALID_PARAMETER);
        }
    } else {
        if (argc != (file_controls_stage ? 5 : 2) || (wcscmp(argv[1], L"run") && wcscmp(argv[1], L"registry-read") &&
                wcscmp(argv[1], L"registry-restricted") && wcscmp(argv[1], L"restricted-network") &&
                !ordinary_restricted && socket_policy < 0 && !socket_share))
            fail("arguments", ERROR_INVALID_PARAMETER);
        restricted_network = !file_controls_stage && (ordinary_restricted || !wcscmp(argv[1], L"restricted-network"));
        restricted_mode = ordinary_restricted || (socket_share && peer_policy < 0) || peer_policy == 3 ||
            socket_policy == 2 || restricted_network || !wcscmp(argv[1], L"registry-restricted");
        registry_mode = peer_policy >= 0 || socket_policy >= 0 || restricted_mode || !wcscmp(argv[1], L"registry-read");
    }
    if (report_pipe) check_child_environment();
#if defined(CM_DELAY_DIAGNOSTIC)
    if (restricted_code_files || installer_files) check_delayed_imports();
#endif
    if (installer_files && !report_pipe) startup_diagnostics(TRUE);
    if (installer_files && report_pipe && !wcscmp(argv[1], L"client")) {
        check_file_controls(TRUE);
        message(9, file_path_checks, "file-path-checks");
        message(10, compiler_creation_checks, "compiler-creation-checks");
    }
    WSADATA winsock;
    int error = WSAStartup(MAKEWORD(2, 2), &winsock);
    if (error && installer_files && report_pipe) startup_diagnostics(FALSE);
    if (error) fail(!report_pipe ? "winsock-startup-outside" :
        socket_share ? "winsock-startup-socket-share" : socket_policy >= 0 ? "winsock-startup-socket" :
        !wcscmp(argv[1], L"control") ? "winsock-startup-control" :
        !wcscmp(argv[1], L"provider") ? "winsock-startup-provider" : "winsock-startup-client", (DWORD)error);
    if (report_pipe) {
        if (socket_share) {
            // shortcut: one existing parent/child channel; qualify reconnect and isolation before product use.
            if (read_marker(L"private-input.txt") || read_marker(L"all-packages.txt") !=
                    (DWORD)(peer_policy == 0 || peer_policy == 1 ? ERROR_SUCCESS : ERROR_ACCESS_DENIED))
                fail("socket-share-file-control", ERROR_INVALID_DATA);
            if (peer_policy < 0 || peer_policy == 3) {
                LSTATUS access = open_host_environment(KEY_QUERY_VALUE);
                if (access != ERROR_ACCESS_DENIED) fail("socket-share-host-env-read", (DWORD)access);
                access = open_host_environment(KEY_SET_VALUE);
                if (access != ERROR_ACCESS_DENIED) fail("socket-share-host-env-write", (DWORD)access);
            }
            SOCKET direct = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            DWORD direct_error = direct == INVALID_SOCKET ? (DWORD)WSAGetLastError() : 0;
            if (direct != INVALID_SOCKET && closesocket(direct))
                fail("socket-share-direct-close", (DWORD)WSAGetLastError());
            if (peer_policy < 0 && direct_error != WSAEACCES) fail("socket-share-direct-denial", direct_error);
            WSAPROTOCOL_INFOW info = {0};
            DWORD received = 0;
            if (!ReadFile(socket_info_reader, &info, (DWORD)sizeof(info), &received, NULL))
                fail("socket-share-info-read", GetLastError());
            if (received != sizeof(info)) fail("socket-share-info-size", ERROR_INVALID_DATA);
            CloseHandle(socket_info_reader); socket_info_reader = NULL;
            SOCKET channel = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                &info, 0, WSA_FLAG_OVERLAPPED);
            if (channel == INVALID_SOCKET) fail("socket-share-reconstruct", (DWORD)WSAGetLastError());
            struct sockaddr_in peer = {0};
            int peer_size = sizeof(peer);
            if (getpeername(channel, (struct sockaddr *)&peer, &peer_size))
                fail("socket-share-peer", (DWORD)WSAGetLastError());
            if (peer_size != (int)sizeof(peer))
                fail("socket-share-peer-size", (DWORD)peer_size);
            if (peer.sin_family != AF_INET)
                fail("socket-share-peer-family", (DWORD)peer.sin_family);
            if (peer_policy >= 0) {
                message(4, direct_error, "socket-observation");
                message(6, (DWORD)ntohl(peer.sin_addr.s_addr), "shared-peer-address");
                message(7, (DWORD)ntohs(peer.sin_port), "shared-peer-port");
                if (closesocket(channel)) fail("shared-peer-close", (DWORD)WSAGetLastError());
                message(3, 0, "complete");
                WSACleanup();
                return 0;
            }
            if (socket_transfer) {
                message(6, (DWORD)ntohl(peer.sin_addr.s_addr), "shared-peer-address");
                message(7, (DWORD)ntohs(peer.sin_port), "shared-peer-port");
            }
            // Transfer mode binds the endpoint in the parent and records the child's metadata separately.
            if (!socket_transfer || peer.sin_addr.s_addr || peer.sin_port) {
                if (peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
                    fail("socket-share-peer-address", (DWORD)ntohl(peer.sin_addr.s_addr));
                if (!peer.sin_port)
                    fail("socket-share-peer-port", (DWORD)ntohs(peer.sin_port));
            }
            DWORD timeout = 3000;
            if (setsockopt(channel, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) ||
                    setsockopt(channel, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)))
                fail("socket-share-timeout", (DWORD)WSAGetLastError());
            message(5, 0, "shared-socket-ready");
            exchange(channel, "", 0, request, sizeof(request) - 1);
            exchange(channel, response, sizeof(response) - 1, "", 0);
            if (closesocket(channel)) fail("socket-share-close", (DWORD)WSAGetLastError());
            message(3, 0, "complete");
            WSACleanup();
            return 0;
        }
        if (socket_policy >= 0) {
            if (wcscmp(argv[1], L"socket")) fail("socket-role", ERROR_INVALID_PARAMETER);
            if (read_marker(L"private-input.txt") ||
                    read_marker(L"all-packages.txt") != (DWORD)(socket_policy ? ERROR_ACCESS_DENIED : ERROR_SUCCESS))
                fail("socket-file-control", ERROR_INVALID_DATA);
            SOCKET probe = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            DWORD observation = probe == INVALID_SOCKET ? (DWORD)WSAGetLastError() : 0;
            if (probe == INVALID_SOCKET && !observation) fail("socket-error-missing", ERROR_INVALID_DATA);
            if (probe != INVALID_SOCKET && closesocket(probe)) fail("socket-close", (DWORD)WSAGetLastError());
            message(4, observation, "socket-observation");
            message(3, 0, "complete");
            WSACleanup();
            return 0;
        }
        if (registry_mode && (!wcscmp(argv[1], L"provider") || !wcscmp(argv[1], L"client"))) {
            BOOL provider_role = !wcscmp(argv[1], L"provider");
            LSTATUS access = open_host_environment(KEY_QUERY_VALUE);
            if (access != ERROR_ACCESS_DENIED)
                fail(provider_role ? "provider-host-env-read-handle" : "client-host-env-read-handle", (DWORD)access);
            access = open_host_environment(KEY_SET_VALUE);
            if (access != ERROR_ACCESS_DENIED)
                fail(provider_role ? "provider-host-env-write-handle" : "client-host-env-write-handle", (DWORD)access);
        }
        if (restricted_mode && (!wcscmp(argv[1], L"provider") || !wcscmp(argv[1], L"client"))) {
            if (read_marker(L"private-input.txt") || read_marker(L"all-packages.txt") != ERROR_ACCESS_DENIED)
                fail(!wcscmp(argv[1], L"provider") ? "provider-restricted-file" : "client-restricted-file", ERROR_INVALID_DATA);
            if (!restricted_network) {
                if (file_controls_stage && !installer_files && !wcscmp(argv[1], L"client")) {
                    check_file_controls(TRUE);
                    message(9, file_path_checks, "file-path-checks");
                    message(10, compiler_creation_checks, "compiler-creation-checks");
                }
                message(3, 0, "complete");
                WSACleanup();
                return 0;
            }
        }
        if (!wcscmp(argv[1], L"control")) {
            if (read_marker(L"all-packages.txt") || read_marker(L"private-input.txt"))
                fail("ordinary-container-file-positive", ERROR_ACCESS_DENIED);
        } else if (!wcscmp(argv[1], L"provider")) {
            unsigned short port = 0;
            SOCKET server = listener(&port, TRUE);
            message(1, port, "internal-provider-ready");
            SOCKET connection = accept(server, NULL, NULL);
            if (connection == INVALID_SOCKET) fail("provider-accept", (DWORD)WSAGetLastError());
            DWORD timeout = 3000;
            if (setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) ||
                    setsockopt(connection, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)))
                fail("provider-timeout", (DWORD)WSAGetLastError());
            char buffer[sizeof(request) - 1];
            size_t offset = 0;
            while (offset < sizeof(buffer)) {
                int count = recv(connection, buffer + offset, (int)(sizeof(buffer) - offset), 0);
                if (count <= 0) fail("provider-request", (DWORD)WSAGetLastError());
                offset += (size_t)count;
            }
            if (memcmp(buffer, request, sizeof(buffer))) fail("provider-request-bytes", ERROR_INVALID_DATA);
            offset = 0;
            while (offset < sizeof(response) - 1) {
                int count = send(connection, response + offset, (int)(sizeof(response) - 1 - offset), 0);
                if (count <= 0) fail("provider-response", (DWORD)WSAGetLastError());
                offset += (size_t)count;
            }
            closesocket(connection); closesocket(server);
        } else if (!wcscmp(argv[1], L"client")) {
            if (read_marker(L"private-input.txt") || read_marker(L"all-packages.txt") != ERROR_ACCESS_DENIED)
                fail("lpac-opt-out-file-control", ERROR_INVALID_DATA);
            unsigned long provider = wcstoul(argv[3], NULL, 10), canary = wcstoul(argv[4], NULL, 10);
            if (!provider || provider > 65535 || !canary || canary > 65535) fail("ports", ERROR_INVALID_DATA);
            SOCKET connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            error = connect_bounded(connection, (unsigned short)provider);
            if (error) fail("internal-provider-connect", (DWORD)error);
            exchange(connection, request, sizeof(request) - 1, response, sizeof(response) - 1);
            closesocket(connection);
            connection = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            error = connect_bounded(connection, (unsigned short)canary);
            if (closesocket(connection) && ordinary_restricted) fail("outside-probe-close", (DWORD)WSAGetLastError());
            if (ordinary_restricted) {
                if (error != WSAETIMEDOUT) fail("outside-canary-timeout", (DWORD)error);
                message(8, (DWORD)error, "outside-connect-observed");
            } else if (error != WSAEACCES) fail("outside-canary-denial", (DWORD)error);
        } else fail("child-role", ERROR_INVALID_PARAMETER);
        message(3, 0, "complete");
        WSACleanup();
        return 0;
    }
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) fail("owner-token", GetLastError());
    owner = token_info(token, TokenUser);
    DWORD *container = token_info(token, TokenIsAppContainer);
    if (*container) fail("outside-launcher-token", ERROR_INVALID_DATA);
    free(container); CloseHandle(token);
    if (registry_mode) {
        if (socket_policy < 0 && (peer_policy < 0 || peer_policy == 3)) {
            LSTATUS access = open_host_environment(KEY_QUERY_VALUE);
            if (access != ERROR_SUCCESS) fail("outside-host-env-read-handle", (DWORD)access);
            access = open_host_environment(KEY_SET_VALUE);
            if (access != ERROR_SUCCESS) fail("outside-host-env-write-handle", (DWORD)access);
        }
        if (!ordinary_restricted) derive_registry_capability();
    }
    if (!SetEnvironmentVariableW(L"CM_LPAC_ENV_CANARY", L"must-not-inherit")) fail("outside-env-canary", GetLastError());
    unsigned char random[16];
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG))
        fail("fresh-profile-name", ERROR_GEN_FAILURE);
    if (wcscpy_s(profile, ARRAYSIZE(profile), L"CM.WX.LPAC.")) fail("profile-name", ERROR_INVALID_DATA);
    for (size_t i = 0; i < sizeof(random); ++i)
        if (swprintf_s(profile + 11 + i * 2, ARRAYSIZE(profile) - 11 - i * 2, L"%02x", (unsigned int)random[i]) != 2)
            fail("profile-name", ERROR_INVALID_DATA);
    HRESULT result = CreateAppContainerProfile(profile, profile, L"CM bounded network fixture", NULL, 0, &package_sid);
    if (FAILED(result)) fail("fresh-profile-create", (DWORD)result);
    profile_created = TRUE;
    if (restricted_mode) prepare_restricted_token();
    private_acl(root, package_sid, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
    private_acl(executable, package_sid, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
    BYTE all_packages[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(all_packages);
    if (!CreateWellKnownSid(WinBuiltinAnyPackageSid, NULL, all_packages, &sid_size)) fail("all-packages-sid", GetLastError());
    create_marker(L"private-input.txt", package_sid);
    create_marker(L"all-packages.txt", all_packages);
    if (read_marker(L"private-input.txt") || read_marker(L"all-packages.txt")) fail("outside-file-baseline", ERROR_INVALID_DATA);
    if (restricted_mode && private_sid_file_grants != 3) fail("private-sid-file-grants", ERROR_INVALID_DATA);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    job = CreateJobObjectW(NULL, NULL);
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        fail("kill-on-close-job", GetLastError());
    if (file_controls_stage) prepare_file_controls();
    DWORD socket_observation = 0, peer_address = 0, peer_port = 0, parent_peer_port = 0;
    if (socket_share) {
        unsigned short port = 0;
        SOCKET server = listener(&port, FALSE);
        shared_peer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (shared_peer == INVALID_SOCKET) fail("socket-share-source", (DWORD)WSAGetLastError());
        error = connect_bounded(shared_peer, port);
        if (error) fail("socket-share-connect", (DWORD)error);
        shared_source = accept(server, NULL, NULL);
        if (shared_source == INVALID_SOCKET) fail("socket-share-accept", (DWORD)WSAGetLastError());
        DWORD timeout = 3000;
        if (setsockopt(shared_source, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) ||
                setsockopt(shared_source, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout)))
            fail("socket-share-retained-timeout", (DWORD)WSAGetLastError());
        if (closesocket(server)) fail("socket-share-listener-close", (DWORD)WSAGetLastError());
        if (peer_policy >= 0 || socket_transfer) {
            struct sockaddr_in peer = {0};
            int size = sizeof(peer);
            if (getpeername(shared_peer, (struct sockaddr *)&peer, &size))
                fail("shared-parent-peer", (DWORD)WSAGetLastError());
            if (size != (int)sizeof(peer) || peer.sin_family != AF_INET ||
                    peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || !peer.sin_port)
                fail("shared-parent-loopback", ERROR_INVALID_DATA);
            parent_peer_port = (DWORD)ntohs(peer.sin_port);
        }
        SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
        if (!CreatePipe(&socket_info_reader, &socket_info_writer, &security, 0) ||
                !SetHandleInformation(socket_info_writer, HANDLE_FLAG_INHERIT, 0))
            fail("socket-share-info-pipe", GetLastError());
        Child *child = spawn(0, L"socket-share", peer_policy < 0 || peer_policy >= 2, 0, 0);
        CloseHandle(socket_info_reader); socket_info_reader = NULL;
        WSAPROTOCOL_INFOW info = {0};
        if (WSADuplicateSocketW(shared_peer, child->process.dwProcessId, &info))
            fail("socket-share-duplicate", (DWORD)WSAGetLastError());
        DWORD written = 0;
        if (!WriteFile(socket_info_writer, &info, (DWORD)sizeof(info), &written, NULL))
            fail("socket-share-info-write", GetLastError());
        if (written != sizeof(info)) fail("socket-share-info-size", ERROR_INVALID_DATA);
        CloseHandle(socket_info_writer); socket_info_writer = NULL;
        if (socket_transfer) {
            peer_address = receive(child, 6);
            peer_port = receive(child, 7);
            if ((peer_address || peer_port) &&
                    (peer_address != INADDR_LOOPBACK || peer_port != parent_peer_port))
                fail("shared-transfer-peer-tuple", ERROR_INVALID_DATA);
        }
        if (peer_policy >= 0) {
            socket_observation = receive(child, 4);
            peer_address = receive(child, 6);
            peer_port = receive(child, 7);
        } else if (receive(child, 5)) fail("socket-share-ready", ERROR_INVALID_DATA);
        // The originating descriptor stays open until the target reconstructs it.
        if (closesocket(shared_peer)) fail("socket-share-origin-close", (DWORD)WSAGetLastError());
        shared_peer = INVALID_SOCKET;
        if (peer_policy < 0)
            exchange(shared_source, request, sizeof(request) - 1, response, sizeof(response) - 1);
        if (closesocket(shared_source)) fail("socket-share-source-close", (DWORD)WSAGetLastError());
        shared_source = INVALID_SOCKET;
        finished(child);
    } else if (socket_policy >= 0) {
        Child *child = spawn(0, L"socket", socket_policy != 0, 0, 0);
        socket_observation = receive(child, 4);
        finished(child);
    } else if (restricted_mode && !restricted_network) {
        finished(spawn(0, L"control", FALSE, 0, 0));
        if (!installer_files) finished(spawn(1, L"provider", !ordinary_restricted, 0, 0));
        Child *client = spawn(2, L"client", !ordinary_restricted, 0, 0);
        if (file_controls_stage && (receive(client, 9) != file_path_checks || receive(client, 10) != compiler_creation_checks))
            fail("child-file-control-count", ERROR_INVALID_DATA);
        if (installer_files) file_diagnostic_done = TRUE;
        finished(client);
        if (installer_files) finished(spawn(1, L"provider", !ordinary_restricted, 0, 0));
    } else {
        unsigned short canary_port = 0;
        SOCKET canary = listener(&canary_port, FALSE), baseline = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        error = connect_bounded(baseline, canary_port);
        if (error) fail("outside-network-baseline", (DWORD)error);
        SOCKET accepted = accept(canary, NULL, NULL);
        if (accepted == INVALID_SOCKET) fail("outside-baseline-accept", (DWORD)WSAGetLastError());
        closesocket(accepted); closesocket(baseline);
        finished(spawn(0, L"control", FALSE, 0, 0));
        Child *provider = spawn(1, L"provider", !ordinary_restricted, 0, 0);
        DWORD port = receive(provider, 1);
        if (!port || port > 65535) fail("provider-port", ERROR_INVALID_DATA);
        Child *client = spawn(2, L"client", !ordinary_restricted, (unsigned short)port, canary_port);
        if (ordinary_restricted && receive(client, 8) != (DWORD)WSAETIMEDOUT)
            fail("outside-timeout-observation", ERROR_INVALID_DATA);
        finished(client);
        finished(provider);
        fd_set readable;
        struct timeval now = {0, 0};
        FD_ZERO(&readable); FD_SET(canary, &readable);
        if (select(0, &readable, NULL, NULL, &now) != 0) fail("outside-unexpected-accept", ERROR_INVALID_DATA);
        if (ordinary_restricted) {
            // A timeout alone cannot distinguish isolation from an unavailable listener.
            baseline = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            error = connect_bounded(baseline, canary_port);
            if (error) fail("outside-post-network-baseline", (DWORD)error);
            accepted = accept(canary, NULL, NULL);
            if (accepted == INVALID_SOCKET) fail("outside-post-baseline-accept", (DWORD)WSAGetLastError());
            if (closesocket(accepted) || closesocket(baseline)) fail("outside-post-baseline-close", (DWORD)WSAGetLastError());
            FD_ZERO(&readable); FD_SET(canary, &readable);
            if (select(0, &readable, NULL, NULL, &now) != 0) fail("outside-post-unexpected-accept", ERROR_INVALID_DATA);
        }
        closesocket(canary);
    }
    result = DeleteAppContainerProfile(profile);
    if (FAILED(result)) fail("owned-profile-delete", (DWORD)result);
    profile_created = FALSE;
    cleanup(); WSACleanup();
    if (peer_policy >= 0) {
        printf("{\"status\":\"observed\",\"gate\":\"lpac-shared-peer-observation\",\"mode\":\"%ls\","
            "\"appcontainer\":%s,\"lpac\":%s,"
            "\"outside_token_checks\":1,\"outside_restricted_token_checks\":%u,\"capability_count\":%u,"
            "\"inherited_handle_count\":2,\"environment_allowlist_count\":%zu,"
            "\"environment_canary_not_inherited\":true,\"file_controls_checked\":true,"
            "\"pid_bound_socket_share\":true,\"direct_socket_error\":%lu,"
            "\"parent_peer_address\":2130706433,\"parent_peer_port\":%lu,"
            "\"peer_size\":16,\"peer_family\":2,\"peer_address\":%lu,\"peer_port\":%lu,"
            "\"profile_deleted\":true,\"http\":\"not_run\",\"network\":\"not_run\","
            "\"full_isolation\":\"not_run\",\"product\":\"not_run\"}\n",
            peer_modes[peer_policy], peer_policy ? "true" : "false", peer_policy >= 2 ? "true" : "false",
            peer_policy == 3 ? 1u : 0u, peer_policy >= 2 ? 1u : 0u,
            ARRAYSIZE(environment_names), socket_observation, parent_peer_port, peer_address, peer_port);
        return 0;
    }
    if (socket_share) {
        char metadata[256] = "";
        if (socket_transfer && _snprintf_s(metadata, sizeof(metadata), _TRUNCATE,
                ",\"parent_endpoint_checked\":true,\"parent_peer_address\":2130706433,\"parent_peer_port\":%lu,"
                "\"peer_size\":16,\"peer_family\":2,\"peer_address\":%lu,\"peer_port\":%lu",
                parent_peer_port, peer_address, peer_port) < 0)
            fail("shared-transfer-record-bound", ERROR_INVALID_DATA);
        printf("{\"status\":\"pass\",\"gate\":\"%s\","
            "\"outside_token_checks\":1,\"outside_restricted_token_checks\":1,"
            "\"restricting_sid_count\":3,\"restricting_sid_policy\":\"world-users-private-nt\","
            "\"private_sid_group_absence_checked\":true,\"private_sid_file_grants\":%lu,"
            "\"private_sid_default_dacl_checked\":true,\"privilege_allowlist_checked\":true,"
            "\"capability_count\":1,\"capability\":\"registryRead\",\"inherited_handle_count\":2,"
            "\"environment_allowlist_count\":%zu,\"environment_canary_not_inherited\":true,"
            "\"lpac_opt_out_file_denied\":true,\"private_file_positive\":true,"
            "\"host_registry_baseline\":true,\"host_environment_read_error\":5,\"host_environment_write_open_error\":5,"
            "\"direct_socket_error\":10013,\"pid_bound_socket_share\":true,\"parent_child_http_positive\":true,"
            "\"profile_deleted\":true,\"network_qualification\":\"not_run\","
            "\"full_isolation\":\"not_run\",\"product\":\"not_run\"%s}\n",
            socket_transfer ? "lpac-shared-transfer-control" : "lpac-socket-share-control",
            private_sid_file_grants, ARRAYSIZE(environment_names), metadata);
        return 0;
    }
    if (socket_policy >= 0) {
        printf("{\"status\":\"observed\",\"gate\":\"lpac-socket-availability-control\","
            "\"mode\":\"%ls\",\"socket_error\":%lu,\"network\":\"not_run\","
            "\"full_isolation\":\"not_run\",\"product\":\"not_run\"}\n",
            socket_modes[socket_policy], socket_observation);
        return 0;
    }
    if (restricted_mode) {
        printf("{\"status\":\"pass\",\"gate\":\"%s\","
            "\"outside_token_checks\":3,\"outside_restricted_token_checks\":2,"
            "\"restricting_sid_count\":3,\"restricting_sid_policy\":\"%s\","
            "\"private_sid_group_absence_checked\":true,\"private_sid_file_grants\":%lu,"
            "\"private_sid_default_dacl_checked\":true,"
            "\"privilege_allowlist_checked\":true,\"capability_count\":%u%s,"
            "\"ordinary_file_positive\":true,\"environment_allowlist_count\":%zu,"
            "\"environment_canary_not_inherited\":true,\"%s\":true,"
            "\"private_file_positive\":true,\"child_winsock_startup_checks\":3,"
            "\"host_registry_baseline\":true,\"host_environment_read_error\":5,"
            "\"host_environment_write_open_error\":5,\"profile_deleted\":true,"
            "\"network\":\"%s\",\"full_isolation\":\"not_run\",\"product\":\"not_run\"%s%s%s%s}\n",
            installer_files ? "restricted-installer-appcontainer-files-control" :
                restricted_code_files ? "restricted-code-appcontainer-files-control" :
                file_controls_stage ? "restricted-appcontainer-files-control" : ordinary_restricted ? "restricted-appcontainer-network-control" :
                restricted_network ? "lpac-restricted-network-control" : "lpac-restricted-registry-control",
            installer_files ? "world-trusted-installer-private-nt" :
                restricted_code_files ? "world-restricted-code-private-nt" : "world-users-private-nt",
            private_sid_file_grants, ordinary_restricted ? 0u : 1u,
            ordinary_restricted ? "" : ",\"capability\":\"registryRead\"",
            ARRAYSIZE(environment_names), ordinary_restricted ? "all_packages_file_denied" : "lpac_opt_out_file_denied",
            restricted_network ? "pass" : "not_run",
            restricted_network ? ordinary_restricted ?
                ",\"provider_http_positive\":true,\"outside_listener_positive\":true,\"outside_connect_error\":10060,"
                "\"outside_denial_observation\":\"bounded_timeout_3_seconds\",\"outside_listener_post_positive\":true,"
                "\"outside_unexpected_accepts\":0" :
                ",\"provider_http_positive\":true,\"outside_listener_positive\":true,"
                "\"outside_connect_error\":10013,\"outside_unexpected_accepts\":0" : "",
            ordinary_restricted ? ",\"all_application_packages_opt_out\":false" : "",
            file_controls_stage ? ",\"outside_file_baselines\":6,\"file_path_checks\":6,\"file_read_error\":5,"
                "\"outside_compiler_creation_baselines\":3,\"compiler_creation_checks\":3,\"compiler_creation_error\":5,"
                "\"source_cache_aliases_checked\":true,\"compiler_executed\":false" : "",
            installer_files ? ",\"system_sid_group_absence_checked\":true" : "");
        return 0;
    }
    printf("{\"status\":\"pass\",\"gate\":\"%s\","
         "\"outside_token_checks\":3,\"capability_count\":%u,\"ordinary_file_positive\":true,"
         "\"environment_allowlist_count\":%zu,\"environment_canary_not_inherited\":true,"
         "\"lpac_opt_out_file_denied\":true,\"private_file_positive\":true,\"provider_http_positive\":true,"
         "\"outside_listener_positive\":true,\"outside_connect_error\":10013,\"outside_unexpected_accepts\":0,"
         "\"profile_deleted\":true,\"full_isolation\":\"not_run\",\"product\":\"not_run\"%s}\n",
         registry_mode ? "lpac-registry-read-network-control" : "lpac-internal-provider-network-control",
         registry_mode ? 1u : 0u, ARRAYSIZE(environment_names), registry_mode ?
         ",\"capability\":\"registryRead\",\"host_registry_baseline\":true,"
         "\"host_environment_read_error\":5,\"host_environment_write_open_error\":5" : "");
    return 0;
}
