#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
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
static HANDLE job, report_pipe;
static Child children[3];
static wchar_t profile[64], executable[MAX_PATH], root[MAX_PATH];
static PSID package_sid;
static TOKEN_USER *owner;
static BOOL profile_created;
static const char request[] = "GET /controlled HTTP/1.0\r\n\r\n";
static const char response[] = "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK";

static void cleanup(void) {
    if (job) { CloseHandle(job); job = NULL; }
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

static SOCKET listener(unsigned short *port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in address = {0};
    int size = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (sock == INVALID_SOCKET || bind(sock, (const struct sockaddr *)&address, sizeof(address)) ||
            listen(sock, 2) || getsockname(sock, (struct sockaddr *)&address, &size))
        fail("listener", (DWORD)WSAGetLastError());
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

static void inspect(Child *child) {
    HANDLE token = NULL;
    BOOL member = FALSE;
    if (!OpenProcessToken(child->process.hProcess, TOKEN_QUERY, &token)) fail("child-token", GetLastError());
    DWORD *container = token_info(token, TokenIsAppContainer);
    TOKEN_APPCONTAINER_INFORMATION *identity = token_info(token, TokenAppContainerSid);
    TOKEN_GROUPS *capabilities = token_info(token, TokenCapabilities);
    TOKEN_MANDATORY_LABEL *integrity = token_info(token, TokenIntegrityLevel);
    DWORD level = *GetSidSubAuthority(integrity->Label.Sid,
        (DWORD)(*GetSidSubAuthorityCount(integrity->Label.Sid) - 1));
    if (*container != 1 || !identity->TokenAppContainer || !EqualSid(identity->TokenAppContainer, package_sid) ||
            capabilities->GroupCount != 0 || level != SECURITY_MANDATORY_LOW_RID ||
            !IsProcessInJob(child->process.hProcess, job, &member) || !member)
        fail("outside-token-or-job", ERROR_INVALID_DATA);
    free(container); free(identity); free(capabilities); free(integrity);
    CloseHandle(token);
}

static Child *spawn(size_t index, const wchar_t *role, BOOL lpac, unsigned short provider, unsigned short canary) {
    Child *child = &children[index];
    HANDLE writer = NULL;
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    SECURITY_CAPABILITIES capabilities = {0};
    STARTUPINFOEXW startup = {0};
    SIZE_T size = 0;
    DWORD policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    wchar_t command[1024], environment[MAX_PATH + 32], windows[MAX_PATH];
    if (!CreatePipe(&child->reader, &writer, &security, 0) ||
            !SetHandleInformation(child->reader, HANDLE_FLAG_INHERIT, 0)) fail("report-pipe", GetLastError());
    DWORD length = GetWindowsDirectoryW(windows, ARRAYSIZE(windows));
    if (!length || length >= ARRAYSIZE(windows)) fail("system-root", GetLastError());
    int count = _snwprintf_s(environment, ARRAYSIZE(environment), _TRUNCATE, L"SystemRoot=%ls", windows);
    if (count < 0 || (size_t)count + 1 >= ARRAYSIZE(environment)) fail("child-env", ERROR_INVALID_DATA);
    environment[count + 1] = L'\0';
    if (_snwprintf_s(command, ARRAYSIZE(command), _TRUNCATE, L"\"%ls\" %ls %llu %u %u", executable, role,
            (unsigned long long)(UINT_PTR)writer, (unsigned int)provider, (unsigned int)canary) < 0)
        fail("child-command", ERROR_INVALID_DATA);
    DWORD attributes = lpac ? 3 : 2;
    InitializeProcThreadAttributeList(NULL, attributes, 0, &size);
    startup.lpAttributeList = malloc(size);
    if (!startup.lpAttributeList || !InitializeProcThreadAttributeList(startup.lpAttributeList, attributes, 0, &size))
        fail("child-attributes", GetLastError());
    capabilities.AppContainerSid = package_sid;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &capabilities, sizeof(capabilities), NULL, NULL) ||
            !UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            &writer, sizeof(writer), NULL, NULL) ||
            (lpac && !UpdateProcThreadAttribute(startup.lpAttributeList, 0,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &policy, sizeof(policy), NULL, NULL)))
        fail("child-attribute-update", GetLastError());
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    if (!CreateProcessW(executable, command, NULL, NULL, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            environment, root, &startup.StartupInfo, &child->process)) fail("child-create", GetLastError());
    DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    CloseHandle(writer);
    if (!AssignProcessToJobObject(job, child->process.hProcess)) fail("child-job", GetLastError());
    inspect(child);
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
    if (argc == 5) {
        wchar_t *end = NULL;
        report_pipe = (HANDLE)(UINT_PTR)wcstoull(argv[2], &end, 10);
        if (!report_pipe || !end || *end) fail("report-argument", ERROR_INVALID_DATA);
    } else if (argc != 2 || wcscmp(argv[1], L"run")) fail("arguments", ERROR_INVALID_PARAMETER);
    WSADATA winsock;
    int error = WSAStartup(MAKEWORD(2, 2), &winsock);
    if (error) fail("winsock-startup", (DWORD)error);
    if (report_pipe) {
        if (!wcscmp(argv[1], L"control")) {
            if (read_marker(L"all-packages.txt") || read_marker(L"private-input.txt"))
                fail("ordinary-container-file-positive", ERROR_ACCESS_DENIED);
        } else if (!wcscmp(argv[1], L"provider")) {
            unsigned short port = 0;
            SOCKET server = listener(&port);
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
    unsigned short canary_port = 0;
    SOCKET canary = listener(&canary_port), baseline = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
    result = DeleteAppContainerProfile(profile);
    if (FAILED(result)) fail("owned-profile-delete", (DWORD)result);
    profile_created = FALSE;
    cleanup(); WSACleanup();
    puts("{\"status\":\"pass\",\"gate\":\"lpac-internal-provider-network-control\","
         "\"outside_token_checks\":3,\"capability_count\":0,\"ordinary_file_positive\":true,"
         "\"lpac_opt_out_file_denied\":true,\"private_file_positive\":true,\"provider_http_positive\":true,"
         "\"outside_listener_positive\":true,\"outside_connect_error\":10013,\"outside_unexpected_accepts\":0,"
         "\"profile_deleted\":true,\"full_isolation\":\"not_run\",\"product\":\"not_run\"}");
    return 0;
}
