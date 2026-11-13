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

#if !defined(_M_X64)
#error This bounded fixture requires native x64 MSVC
#endif

typedef struct { DWORD kind, value; char gate[48]; } Message;
typedef struct { PROCESS_INFORMATION process; HANDLE reader; } Child;
static HANDLE job, report_pipe, restricted_base;
static Child children[3];
static wchar_t profile[64], executable[MAX_PATH], root[MAX_PATH];
static PSID package_sid;
static PSID registry_sid;
static TOKEN_USER *owner;
static BOOL profile_created;
static BOOL registry_mode;
static BOOL restricted_mode;
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
    if (profile_created) {
        HRESULT result = DeleteAppContainerProfile(profile);
        if (FAILED(result)) fprintf(stderr, "Owned profile cleanup failed; error=%lu\n", (DWORD)result);
    }
    if (package_sid) FreeSid(package_sid);
    LocalFree(registry_sid); registry_sid = NULL;
    free(owner);
}

static void message(DWORD kind, DWORD value, const char *gate) {
    Message item = {kind, value, {0}};
    DWORD written = 0;
    if (strcpy_s(item.gate, sizeof(item.gate), gate) != 0 ||
            !WriteFile(report_pipe, &item, (DWORD)sizeof(item), &written, NULL) || written != sizeof(item))
        ExitProcess(3);
}

static void fail(const char *gate, DWORD error) {
    if (report_pipe) message(2, error, gate);
    else {
        fprintf(stderr, "LPAC mechanism failed at %s; error=%lu\n", gate, error);
        cleanup();
    }
    ExitProcess(2);
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
    BOOL seen[3] = {0};
    LUID traverse;
    if (sids->GroupCount != 3 || !EqualSid(user->User.Sid, owner->User.Sid))
        fail_restriction(role, "identity-or-count", ERROR_INVALID_DATA);
    for (DWORD i = 0; i < sids->GroupCount; ++i) {
        PSID sid = sids->Groups[i].Sid;
        int index = IsWellKnownSid(sid, WinWorldSid) ? 0 :
            IsWellKnownSid(sid, WinBuiltinUsersSid) ? 1 : EqualSid(sid, package_sid) ? 2 : -1;
        if (index < 0 || seen[index] || (sids->Groups[i].Attributes & SE_GROUP_USE_FOR_DENY_ONLY))
            fail_restriction(role, "sid-policy", ERROR_INVALID_DATA);
        seen[index] = TRUE;
    }
    if (!LookupPrivilegeValueW(NULL, L"SeChangeNotifyPrivilege", &traverse))
        fail_restriction(role, "privilege-name", GetLastError());
    for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
        LUID_AND_ATTRIBUTES item = privileges->Privileges[i];
        if ((item.Attributes & SE_PRIVILEGE_ENABLED) &&
                (item.Luid.LowPart != traverse.LowPart || item.Luid.HighPart != traverse.HighPart))
            fail_restriction(role, "enabled-privilege", ERROR_INVALID_DATA);
    }
    free(sids); free(privileges); free(user);
}

static void prepare_restricted_token(void) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &token))
        fail("restricted-source-token", GetLastError());
    TOKEN_GROUPS *existing = token_info(token, TokenRestrictedSids);
    if (existing->GroupCount) fail("restricted-source-intersection", ERROR_INVALID_DATA);
    free(existing);
    BYTE world[SECURITY_MAX_SID_SIZE], users[SECURITY_MAX_SID_SIZE];
    DWORD world_size = sizeof(world), users_size = sizeof(users);
    if (!CreateWellKnownSid(WinWorldSid, NULL, world, &world_size) ||
            !CreateWellKnownSid(WinBuiltinUsersSid, NULL, users, &users_size))
        fail("restricted-well-known-sids", GetLastError());
    SID_AND_ATTRIBUTES sids[3] = {{world, 0}, {users, 0}, {package_sid, 0}};
    if (!CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 3, sids, &restricted_base))
        fail("restricted-token-create", GetLastError());
    CloseHandle(token);
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
    EXPLICIT_ACCESSW entries[2] = {0};
    PACL acl = NULL;
    for (size_t i = 0; i < ARRAYSIZE(entries); ++i) {
        entries[i].grfAccessMode = GRANT_ACCESS;
        entries[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    }
    entries[0].grfAccessPermissions = FILE_ALL_ACCESS;
    entries[0].Trustee.ptstrName = (LPWSTR)owner->User.Sid;
    entries[1].grfAccessPermissions = access;
    entries[1].Trustee.ptstrName = (LPWSTR)allowed;
    DWORD error = SetEntriesInAclW(2, entries, NULL, &acl);
    if (error) fail("owned-acl-build", error);
    error = SetNamedSecurityInfoW(path, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL);
    LocalFree(acl);
    if (error) fail("owned-acl-set", error);
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
    if (lpac && restricted_mode)
        inspect_restrictions(token, !wcscmp(role, L"provider") ? "provider" : "client");
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
    wchar_t command[1024], environment[4096];
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
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE, L"\"%ls\" %ls %llu %u %u%ls", executable, role,
            (unsigned long long)(UINT_PTR)writer, (unsigned int)provider, (unsigned int)canary,
            restricted_mode ? L" registry-restricted" : registry_mode ? L" registry-read" : L"") < 0)
        fail("child-command", ERROR_INVALID_DATA);
    DWORD attributes = lpac ? 3 : 2;
    InitializeProcThreadAttributeList(NULL, attributes, 0, &size);
    startup.lpAttributeList = malloc(size);
    if (!startup.lpAttributeList || !InitializeProcThreadAttributeList(startup.lpAttributeList, attributes, 0, &size))
        fail("child-attributes", GetLastError());
    capabilities.AppContainerSid = package_sid;
    if (lpac && registry_mode) {
        capabilities.Capabilities = &registry;
        capabilities.CapabilityCount = 1;
    }
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &capabilities, sizeof(capabilities), NULL, NULL) ||
            !UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            &writer, sizeof(writer), NULL, NULL) ||
            (lpac && !UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &policy, sizeof(policy), NULL, NULL)))
        fail("child-attribute-update", GetLastError());
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
    BOOL created = lpac && restricted_mode ?
        CreateProcessAsUserW(restricted_base, executable, command, NULL, NULL, TRUE, flags,
            environment, root, &startup.StartupInfo, &child->process) :
        CreateProcessW(executable, command, NULL, NULL, TRUE, flags,
            environment, root, &startup.StartupInfo, &child->process);
    if (!created) fail(lpac && restricted_mode ?
        (!wcscmp(role, L"provider") ? "provider-restricted-create" : "client-restricted-create") :
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
    Message item = {0};
    DWORD size = 0;
    if (!ReadFile(child->reader, &item, (DWORD)sizeof(item), &size, NULL)) fail("child-report", GetLastError());
    if (size != sizeof(item) || !memchr(item.gate, 0, sizeof(item.gate)))
        fail("child-report-bytes", ERROR_INVALID_DATA);
    if (item.kind == 2) fail(item.gate, item.value);
    if (item.kind != kind || strcmp(item.gate, kind == 1 ? "internal-provider-ready" : "complete"))
        fail("child-report-kind", ERROR_INVALID_DATA);
    return item.value;
}

static void finished(Child *child) {
    DWORD code = 0;
    DWORD wait = WaitForSingleObject(child->process.hProcess, 30000);
    if (wait != WAIT_OBJECT_0) fail("child-exit-wait", wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError());
    if (!GetExitCodeProcess(child->process.hProcess, &code)) fail("child-exit-code", GetLastError());
    if (code) {
        fprintf(stderr, "Native child exit=%lu\n", code);
        receive(child, 3); fail("child-exit", code);
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
    if (argc == 5 || argc == 6) {
        if (argc == 6) {
            if (wcscmp(argv[5], L"registry-read") && wcscmp(argv[5], L"registry-restricted"))
                fail("child-mode", ERROR_INVALID_PARAMETER);
            registry_mode = TRUE;
            restricted_mode = !wcscmp(argv[5], L"registry-restricted");
        }
        wchar_t *end = NULL;
        report_pipe = (HANDLE)(UINT_PTR)wcstoull(argv[2], &end, 10);
        if (!report_pipe || !end || *end) fail("report-argument", ERROR_INVALID_DATA);
    } else {
        if (argc != 2 || (wcscmp(argv[1], L"run") && wcscmp(argv[1], L"registry-read") &&
                wcscmp(argv[1], L"registry-restricted")))
            fail("arguments", ERROR_INVALID_PARAMETER);
        restricted_mode = !wcscmp(argv[1], L"registry-restricted");
        registry_mode = restricted_mode || !wcscmp(argv[1], L"registry-read");
    }
    if (report_pipe) check_child_environment();
    WSADATA winsock;
    int error = WSAStartup(MAKEWORD(2, 2), &winsock);
    if (error) fail(!report_pipe ? "winsock-startup-outside" :
        !wcscmp(argv[1], L"control") ? "winsock-startup-control" :
        !wcscmp(argv[1], L"provider") ? "winsock-startup-provider" : "winsock-startup-client", (DWORD)error);
    if (report_pipe) {
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
        } else if (!wcscmp(argv[1], L"control")) {
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
            closesocket(connection);
            if (error != WSAEACCES) fail("outside-canary-denial", (DWORD)error);
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
        LSTATUS access = open_host_environment(KEY_QUERY_VALUE);
        if (access != ERROR_SUCCESS) fail("outside-host-env-read-handle", (DWORD)access);
        access = open_host_environment(KEY_SET_VALUE);
        if (access != ERROR_SUCCESS) fail("outside-host-env-write-handle", (DWORD)access);
        derive_registry_capability();
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
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    job = CreateJobObjectW(NULL, NULL);
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        fail("kill-on-close-job", GetLastError());
    if (restricted_mode) {
        finished(spawn(0, L"control", FALSE, 0, 0));
        finished(spawn(1, L"provider", TRUE, 0, 0));
        finished(spawn(2, L"client", TRUE, 0, 0));
    } else {
        unsigned short canary_port = 0;
        SOCKET canary = listener(&canary_port, FALSE), baseline = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        error = connect_bounded(baseline, canary_port);
        if (error) fail("outside-network-baseline", (DWORD)error);
        SOCKET accepted = accept(canary, NULL, NULL);
        if (accepted == INVALID_SOCKET) fail("outside-baseline-accept", (DWORD)WSAGetLastError());
        closesocket(accepted); closesocket(baseline);
        finished(spawn(0, L"control", FALSE, 0, 0));
        Child *provider = spawn(1, L"provider", TRUE, 0, 0);
        DWORD port = receive(provider, 1);
        if (!port || port > 65535) fail("provider-port", ERROR_INVALID_DATA);
        finished(spawn(2, L"client", TRUE, (unsigned short)port, canary_port));
        finished(provider);
        fd_set readable;
        struct timeval now = {0, 0};
        FD_ZERO(&readable); FD_SET(canary, &readable);
        if (select(0, &readable, NULL, NULL, &now) != 0) fail("outside-unexpected-accept", ERROR_INVALID_DATA);
        closesocket(canary);
    }
    result = DeleteAppContainerProfile(profile);
    if (FAILED(result)) fail("owned-profile-delete", (DWORD)result);
    profile_created = FALSE;
    cleanup(); WSACleanup();
    if (restricted_mode) {
        printf("{\"status\":\"pass\",\"gate\":\"lpac-restricted-registry-control\","
            "\"outside_token_checks\":3,\"outside_restricted_token_checks\":2,"
            "\"restricting_sid_count\":3,\"restricting_sid_policy\":\"world-users-package\","
            "\"privilege_allowlist_checked\":true,\"capability_count\":1,\"capability\":\"registryRead\","
            "\"ordinary_file_positive\":true,\"environment_allowlist_count\":%zu,"
            "\"environment_canary_not_inherited\":true,\"lpac_opt_out_file_denied\":true,"
            "\"private_file_positive\":true,\"child_winsock_startup_checks\":3,"
            "\"host_registry_baseline\":true,\"host_environment_read_error\":5,"
            "\"host_environment_write_open_error\":5,\"profile_deleted\":true,"
            "\"network\":\"not_run\",\"full_isolation\":\"not_run\",\"product\":\"not_run\"}\n",
            ARRAYSIZE(environment_names));
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
