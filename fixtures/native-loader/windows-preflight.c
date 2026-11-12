#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef CM_PAYLOAD
__declspec(dllexport) int WINAPI cm_sentinel(void) { return 41; }

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        wchar_t path[4096];
        DWORD length = GetEnvironmentVariableW(L"CM_CONSTRUCTOR_MARKER", path, 4096);
        if (!length || length >= 4096) return FALSE;
        HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) return FALSE;
        DWORD written = 0;
        BOOL ok = WriteFile(file, "constructor41", 13, &written, NULL);
        CloseHandle(file);
        if (!ok || written != 13) return FALSE;
    }
    return TRUE;
}
#else
typedef struct {
    HANDLE parents[96], file;
    size_t count;
    BOOL file_attempted;
    FILE_ID_INFO id;
    LARGE_INTEGER size;
    wchar_t path[4096];
} Pin;

static int rejected(const char *gate, DWORD error) {
    printf("{\"status\":\"rejected\",\"gate\":\"%s\",\"error\":%lu,\"native_executed\":false}\n", gate, error);
    return 2;
}

static int pin(Pin *p, const wchar_t *name) {
    ZeroMemory(p, sizeof(*p));
    p->file = INVALID_HANDLE_VALUE;
    DWORD length = GetFullPathNameW(name, 4096, p->path, NULL);
    if (!length || length >= 4096 || length < 4 || p->path[1] != L':' || p->path[2] != L'\\'
        || _wcsicmp(name, p->path) != 0) { SetLastError(ERROR_INVALID_NAME); return 0; }
    for (DWORD i = 2; i < length; ++i) {
        if (p->path[i] != L'\\') continue;
        wchar_t directory[4096];
        memcpy(directory, p->path, (i + 1) * sizeof(wchar_t));
        directory[i + 1] = 0;
        if (p->count == 96) { SetLastError(ERROR_BUFFER_OVERFLOW); return 0; }
        HANDLE handle = CreateFileW(directory, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (handle == INVALID_HANDLE_VALUE) return 0;
        p->parents[p->count++] = handle;
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, &info)) return 0;
        if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            SetLastError(ERROR_REPARSE_TAG_INVALID); return 0;
        }
    }
    p->file_attempted = TRUE;
    p->file = CreateFileW(p->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (p->file == INVALID_HANDLE_VALUE) return 0;
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(p->file, &info)
        || !GetFileInformationByHandleEx(p->file, FileIdInfo, &p->id, sizeof(p->id))
        || !GetFileSizeEx(p->file, &p->size)) return 0;
    if (GetFileType(p->file) != FILE_TYPE_DISK || info.nNumberOfLinks != 1
        || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        || p->size.QuadPart < 1 || p->size.QuadPart > 32 * 1024 * 1024) {
        SetLastError(ERROR_INVALID_DATA); return 0;
    }
    wchar_t final[4096];
    length = GetFinalPathNameByHandleW(p->file, final, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!length || length >= 4096 || wcsncmp(final, L"\\\\?\\", 4)
        || _wcsicmp(final + 4, p->path)) { SetLastError(ERROR_INVALID_NAME); return 0; }
    return 1;
}

static int sha256(HANDLE file, const wchar_t *expected) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD length = 0, received = 0;
    PUCHAR object = NULL;
    BYTE buffer[16384], digest[32];
    int ok = 0;
    if (wcslen(expected) != 64 || BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0)) goto done;
    if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&length, sizeof(length), &received, 0)) goto done;
    object = (PUCHAR)malloc(length);
    if (!object || BCryptCreateHash(algorithm, &hash, object, length, NULL, 0, 0)) goto done;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &received, NULL)) goto done;
        if (!received) break;
        if (BCryptHashData(hash, buffer, received, 0)) goto done;
    }
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0)) goto done;
    ok = 1;
    for (size_t i = 0; i < 32; ++i) {
        const wchar_t hex[] = L"0123456789abcdef";
        if (expected[2 * i] != hex[digest[i] >> 4] || expected[2 * i + 1] != hex[digest[i] & 15]) ok = 0;
    }
done:
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    free(object);
    return ok;
}

static int load(const wchar_t *path, const wchar_t *expected) {
    Pin p;
    if (!pin(&p, path)) return rejected(p.file_attempted ? "pin-file" : "pin-ancestors", GetLastError());
    if (!sha256(p.file, expected)) return rejected("payload-hash", ERROR_INVALID_DATA);
    puts("{\"status\":\"ready\",\"gate\":\"verified-pin\",\"native_executed\":false}");
    fflush(stdout);
    if (getchar() != 'L') return rejected("load-barrier", ERROR_OPERATION_ABORTED);
    HANDLE current = CreateFileW(p.path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    FILE_ID_INFO id;
    LARGE_INTEGER size;
    if (current == INVALID_HANDLE_VALUE || !GetFileInformationByHandleEx(current, FileIdInfo, &id, sizeof(id))
        || !GetFileSizeEx(current, &size) || memcmp(&id, &p.id, sizeof(id)) || size.QuadPart != p.size.QuadPart)
        return rejected("pinned-identity", ERROR_INVALID_DATA);
    CloseHandle(current);
    HMODULE module = LoadLibraryExW(p.path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module) {
        printf("{\"status\":\"failed\",\"gate\":\"LoadLibraryExW\",\"error\":%lu,\"native_executed\":true}\n", GetLastError());
        return 2;
    }
    typedef int (WINAPI *Sentinel)(void);
    FARPROC address = GetProcAddress(module, "cm_sentinel");
    Sentinel function = NULL;
    _Static_assert(sizeof(function) == sizeof(address), "native function pointer size");
    memcpy(&function, &address, sizeof(function));
    if (!function || function() != 41) return 2;
    puts("{\"status\":\"pass\",\"gate\":\"pinned-system-loader-control\",\"constructor_value\":41,\"native_executed\":true}");
    /* Constructors may publish pointers: handles and module live until process exit. */
    return 0;
}

static int hold(const wchar_t *mode, const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return rejected("writer-control", GetLastError());
    HANDLE mapping = NULL;
    volatile BYTE *view = NULL;
    int mapped = wcscmp(mode, L"mapping") == 0;
    if (mapped) {
        mapping = CreateFileMappingW(file, NULL, PAGE_READWRITE, 0, 0, NULL);
        if (!mapping) return rejected("mapping-control", GetLastError());
        view = (volatile BYTE *)MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 1);
        if (!view) return rejected("mapping-control", GetLastError());
        CloseHandle(file);
        file = INVALID_HANDLE_VALUE;
    }
    puts("{\"status\":\"held\",\"native_executed\":false}");
    fflush(stdout);
    if (getchar() != 'W') return 2;
    DWORD written = 0;
    BYTE changed = 0;
    BOOL ok;
    if (mapped) {
        view[0] = changed;
        ok = FlushViewOfFile((LPCVOID)view, 1);
        UnmapViewOfFile((LPCVOID)view);
        CloseHandle(mapping);
        written = ok ? 1 : 0;
    } else {
        ok = WriteFile(file, &changed, 1, &written, NULL);
        CloseHandle(file);
    }
    printf("{\"status\":\"%s\",\"written\":%lu,\"native_executed\":false}\n", ok && written == 1 ? "mutated" : "failed", written);
    return ok && written == 1 ? 0 : 2;
}

static DWORD blocked_error(BOOL succeeded) { return succeeded ? 0 : GetLastError(); }

static int attack(const wchar_t *file, const wchar_t *parent) {
    HANDLE writer = CreateFileW(file, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    DWORD write_error = writer == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
    DWORD delete_error = blocked_error(DeleteFileW(file));
    wchar_t destination[4096];
    if (swprintf_s(destination, 4096, L"%ls.replacement", file) < 0) return 2;
    DWORD replace_error = blocked_error(MoveFileExW(destination, file, MOVEFILE_REPLACE_EXISTING));
    if (swprintf_s(destination, 4096, L"%ls.moved", file) < 0) return 2;
    DWORD rename_error = blocked_error(MoveFileExW(file, destination, MOVEFILE_REPLACE_EXISTING));
    if (swprintf_s(destination, 4096, L"%ls.moved", parent) < 0) return 2;
    DWORD parent_error = blocked_error(MoveFileExW(parent, destination, 0));
    printf("{\"write_error\":%lu,\"delete_error\":%lu,\"replace_error\":%lu,\"rename_error\":%lu,\"parent_rename_error\":%lu,\"native_executed\":false}\n",
        write_error, delete_error, replace_error, rename_error, parent_error);
    return write_error && delete_error && replace_error && rename_error && parent_error ? 0 : 2;
}

typedef struct {
    HANDLE pipe, ready;
    char text[65536];
    DWORD used, error;
    BOOL overflow;
} Drain;

static DWORD WINAPI drain_output(LPVOID argument) {
    Drain *d = (Drain *)argument;
    char block[1024];
    DWORD length;
    while (ReadFile(d->pipe, block, sizeof(block), &length, NULL) && length) {
        if (d->used + length >= sizeof(d->text)) { d->overflow = TRUE; continue; }
        memcpy(d->text + d->used, block, length);
        d->used += length;
        d->text[d->used] = 0;
        if (strstr(d->text, "CM_READY:96x28")) SetEvent(d->ready);
    }
    d->error = GetLastError();
    return 0;
}

static int terminal_child(void) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE), output = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info = {0};
    BOOL mode_ok = SetConsoleMode(input, ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT);
    DWORD mode_error = mode_ok ? 0 : GetLastError();
    BOOL size_ok = GetConsoleScreenBufferInfo(output, &info);
    DWORD size_error = size_ok ? 0 : GetLastError();
    wchar_t path[4096];
    DWORD length = GetEnvironmentVariableW(L"CM_CI_LOG_DIR", path, 4096);
    if (!length || length >= 4096 || wcscat_s(path, 4096, L"\\conpty-child-state.txt")) return 2;
    FILE *state = NULL;
    if (_wfopen_s(&state, path, L"a") || !state) return 2;
    fprintf(state, "input_type=%lu output_type=%lu mode_ok=%d mode_error=%lu size_ok=%d size_error=%lu buffer=%dx%d window=%dx%d\n",
        GetFileType(input), GetFileType(output), mode_ok, mode_error, size_ok, size_error,
        info.dwSize.X, info.dwSize.Y, info.srWindow.Right - info.srWindow.Left + 1,
        info.srWindow.Bottom - info.srWindow.Top + 1);
    if (fclose(state)) return 2;
    if (!mode_ok || !size_ok || info.dwSize.X != 96 || info.dwSize.Y != 28) return 2;
    puts("CM_READY:96x28"); fflush(stdout);
    int resized = 0, confirmed = 0;
    /* Report the child's deadline before the parent's ten-second exit wait. */
    ULONGLONG deadline = GetTickCount64() + 8000;
    while (!resized || !confirmed) {
        if (GetTickCount64() >= deadline || WaitForSingleObject(input, 1000) == WAIT_FAILED) {
            printf("CM_CHILD_TIMEOUT:resize=%d,key=%d\n", resized, confirmed); fflush(stdout);
            return 2;
        }
        if (WaitForSingleObject(input, 0) != WAIT_OBJECT_0) continue;
        INPUT_RECORD records[16];
        DWORD count;
        if (!ReadConsoleInputW(input, records, 16, &count)) return 2;
        for (DWORD i = 0; i < count; ++i) {
            if (records[i].EventType == WINDOW_BUFFER_SIZE_EVENT
                && records[i].Event.WindowBufferSizeEvent.dwSize.X == 120
                && records[i].Event.WindowBufferSizeEvent.dwSize.Y == 40) resized = 1;
            if (records[i].EventType == KEY_EVENT && records[i].Event.KeyEvent.bKeyDown
                && records[i].Event.KeyEvent.uChar.UnicodeChar == L'Y') confirmed = 1;
        }
        if (!GetConsoleScreenBufferInfo(output, &info)) return 2;
        printf("CM_INPUT:resize=%d,key=%d,size=%dx%d\n", resized, confirmed, info.dwSize.X, info.dwSize.Y);
        fflush(stdout);
    }
    if (!GetConsoleScreenBufferInfo(output, &info) || info.dwSize.X != 120 || info.dwSize.Y != 40) return 2;
    puts("CM_DONE:120x40:Y"); fflush(stdout);
    return 0;
}

static int terminal(void) {
    HANDLE in_read = NULL, in_write = NULL, out_read = NULL, out_write = NULL, thread = NULL;
    HPCON console = NULL;
    PROCESS_INFORMATION process = {0};
    STARTUPINFOEXW startup = {0};
    Drain d = {0};
    HANDLE job = NULL;
    int ok = 0, attributes_ready = 0;
    DWORD exit_code = 999;
    DWORD ready_wait = WAIT_FAILED, child_wait = WAIT_FAILED;
    const char *phase = "setup";
    SIZE_T size = 0;
    COORD initial = {96, 28}, resized = {120, 40};
    if (!CreatePipe(&in_read, &in_write, NULL, 0) || !CreatePipe(&out_read, &out_write, NULL, 0)) goto done;
    if (FAILED(CreatePseudoConsole(initial, in_read, out_write, 0, &console))) goto done;
    CloseHandle(in_read); in_read = NULL;
    CloseHandle(out_write); out_write = NULL;
    d.pipe = out_read;
    d.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!d.ready) goto done;
    thread = CreateThread(NULL, 0, drain_output, &d, 0, NULL);
    if (!thread) goto done;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(size);
    if (!startup.lpAttributeList || !InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &size)) goto done;
    attributes_ready = 1;
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        console, sizeof(console), NULL, NULL)) goto done;
    startup.StartupInfo.cb = sizeof(startup);
    wchar_t executable[4096], command[8192];
    DWORD n = GetModuleFileNameW(NULL, executable, 4096);
    if (!n || n >= 4096 || swprintf_s(command, 8192, L"\"%ls\" terminal-child", executable) < 0) goto done;
    job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) goto done;
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
        NULL, NULL, &startup.StartupInfo, &process)) goto done;
    if (!AssignProcessToJobObject(job, process.hProcess) || ResumeThread(process.hThread) == (DWORD)-1) goto done;
    phase = "wait-ready";
    HANDLE ready_or_exit[] = {d.ready, process.hProcess};
    ready_wait = WaitForMultipleObjects(2, ready_or_exit, FALSE, 10000);
    if (ready_wait != WAIT_OBJECT_0) goto done;
    phase = "resize";
    if (FAILED(ResizePseudoConsole(console, resized))) goto done;
    phase = "write-input";
    DWORD written;
    if (!WriteFile(in_write, "Y", 1, &written, NULL) || written != 1) goto done;
    phase = "wait-child-exit";
    child_wait = WaitForSingleObject(process.hProcess, 10000);
    if (child_wait != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &exit_code) || exit_code != 0) goto done;
    phase = "drain-output";
    ok = 1;
done:
    if (process.hProcess && !ok) {
        if (!GetExitCodeProcess(process.hProcess, &exit_code)) exit_code = 999;
        if (exit_code == STILL_ACTIVE) TerminateProcess(process.hProcess, 2);
    }
    if (in_write) CloseHandle(in_write);
    /* Drain stays active across ClosePseudoConsole on pre/post-26100 systems. */
    if (console) ClosePseudoConsole(console);
    if (thread) {
        if (WaitForSingleObject(thread, 10000) != WAIT_OBJECT_0) {
            CancelSynchronousIo(thread);
            if (WaitForSingleObject(thread, 1000) != WAIT_OBJECT_0) {
                if (job) CloseHandle(job);
                fputs("ConPTY output thread did not terminate\n", stderr);
                ExitProcess(2);
            }
            ok = 0;
        }
        CloseHandle(thread);
    }
    ok = ok && !d.overflow && d.error == ERROR_BROKEN_PIPE && strstr(d.text, "CM_DONE:120x40:Y") != NULL;
    if (!ok) {
        fprintf(stderr, "ConPTY failure phase=%s ready_wait=%lu child_wait=%lu child_exit=%lu output_hex=",
            phase, ready_wait, child_wait, exit_code);
        for (DWORD i = 0; i < d.used; ++i) fprintf(stderr, "%02x", (unsigned int)(unsigned char)d.text[i]);
        fputc('\n', stderr);
    }
    if (out_read) CloseHandle(out_read);
    if (in_read) CloseHandle(in_read);
    if (out_write) CloseHandle(out_write);
    if (d.ready) CloseHandle(d.ready);
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (job) CloseHandle(job);
    if (attributes_ready) DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    printf("{\"status\":\"%s\",\"gate\":\"ConPTY-control\",\"initial_columns\":96,\"initial_rows\":28,\"resized_columns\":120,\"resized_rows\":40,\"input\":\"Y\",\"child_exit_code\":%lu,\"drain_error\":%lu,\"output_bytes\":%lu,\"full_host_tui\":\"not_run\"}\n",
        ok ? "pass" : "failed", exit_code, d.error, d.used);
    return ok ? 0 : 2;
}

int wmain(int argc, wchar_t **argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    USHORT process_machine, native_machine;
    if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine)
        || process_machine != IMAGE_FILE_MACHINE_UNKNOWN || native_machine != IMAGE_FILE_MACHINE_AMD64)
        return rejected("native-x64", ERROR_BAD_EXE_FORMAT);
    if (argc == 2 && !wcscmp(argv[1], L"terminal-child")) return terminal_child();
    if (argc == 2 && !wcscmp(argv[1], L"conpty")) return terminal();
    if (argc == 3 && (!wcscmp(argv[1], L"pin-only") || !wcscmp(argv[1], L"pin-held"))) {
        Pin p;
        if (!pin(&p, argv[2])) return rejected(p.file_attempted ? "pin-file" : "pin-ancestors", GetLastError());
        puts("{\"status\":\"accepted\",\"gate\":\"pin\",\"native_executed\":false}");
        fflush(stdout);
        if (!wcscmp(argv[1], L"pin-held") && getchar() != 'Q') return rejected("pin-barrier", ERROR_OPERATION_ABORTED);
        return 0;
    }
    if (argc == 4 && !wcscmp(argv[1], L"load")) return load(argv[2], argv[3]);
    if (argc == 4 && !wcscmp(argv[1], L"hold")) return hold(argv[2], argv[3]);
    if (argc == 4 && !wcscmp(argv[1], L"attack")) return attack(argv[2], argv[3]);
    return rejected("arguments", ERROR_INVALID_PARAMETER);
}
#endif
