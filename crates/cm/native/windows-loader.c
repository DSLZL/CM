#include "windows-loader.h"
#include <bcrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

int cm_windows_pin(CmWindowsPin *p, const wchar_t *name) {
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

void cm_windows_unpin(CmWindowsPin *p) {
    if (p->file && p->file != INVALID_HANDLE_VALUE) CloseHandle(p->file);
    p->file = INVALID_HANDLE_VALUE;
    while (p->count) CloseHandle(p->parents[--p->count]);
}

int cm_windows_sha256(HANDLE file, const wchar_t *expected) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD length = 0, received = 0;
    PUCHAR object = NULL;
    BYTE buffer[16384], digest[32];
    LARGE_INTEGER zero = {0};
    int ok = 0;
    if (wcslen(expected) != 64 || !SetFilePointerEx(file, zero, NULL, FILE_BEGIN)
        || BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0)) goto done;
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
    if (!SetFilePointerEx(file, zero, NULL, FILE_BEGIN)) ok = 0;
    return ok;
}

int cm_windows_system_module(HMODULE module) {
    wchar_t system[4096], path[4096];
    UINT length = GetSystemDirectoryW(system, 4096);
    DWORD actual = GetModuleFileNameW(module, path, 4096);
    if (!length || length >= 4096 || !actual || actual >= 4096 || actual <= length + 1
        || _wcsnicmp(path, system, length) || path[length] != L'\\') return 0;
    return wcschr(path + length + 1, L'\\') == NULL && wcschr(path + length + 1, L'/') == NULL;
}

int cm_windows_system_dependencies(const wchar_t *csv) {
    wchar_t names[4096];
    if (wcscpy_s(names, 4096, csv)) return -1;
    wchar_t *context = NULL;
    unsigned count = 0;
    for (wchar_t *name = wcstok_s(names, L",", &context); name; name = wcstok_s(NULL, L",", &context)) {
        if (++count > 32 || !wcslen(name) || wcspbrk(name, L"\\/:")) return -1;
        HMODULE module = NULL;
        if (!GetModuleHandleExW(0, name, &module))
            module = LoadLibraryExW(name, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!module || !cm_windows_system_module(module)) return -1;
        /* Trusted system modules remain live through payload loading. */
    }
    return (int)count;
}

CmWindowsPin *cm_windows_pin_open(const wchar_t *path, const wchar_t *expected) {
    CmWindowsPin *p = (CmWindowsPin *)calloc(1, sizeof(*p));
    if (!p) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    if (cm_windows_pin(p, path)) {
        if (cm_windows_sha256(p->file, expected)) return p;
        SetLastError(ERROR_INVALID_DATA);
    }
    DWORD error = GetLastError();
    cm_windows_pin_free(p);
    SetLastError(error);
    return NULL;
}

CmWindowsPin *cm_windows_pin_copy(const unsigned char *bytes, size_t length, unsigned kind) {
    const wchar_t *extensions[] = {L"dll", L"exe", L"jsonl", L"bin"};
    if (!bytes || !length || length > 32 * 1024 * 1024 || kind >= 4) {
        SetLastError(ERROR_INVALID_PARAMETER); return NULL;
    }
    wchar_t temp[4096], directory[4096], path[4096], token[33];
    BYTE random[16];
    DWORD received = GetTempPathW(4096, temp);
    if (!received || received > 4000) return NULL;
    received = GetLongPathNameW(temp, temp, 4096);
    if (!received || received > 4000 || BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG))
        return NULL;
    for (size_t i = 0; i < 16; ++i) {
        const wchar_t hex[] = L"0123456789abcdef";
        token[2 * i] = hex[random[i] >> 4]; token[2 * i + 1] = hex[random[i] & 15];
    }
    token[32] = 0;
    if (swprintf_s(directory, 4096, L"%lscm-%ls", temp, token) < 0
        || swprintf_s(path, 4096, L"%ls\\snapshot.%ls", directory, extensions[kind]) < 0
        || !CreateDirectoryW(directory, NULL)) return NULL;
    CmWindowsPin *p = (CmWindowsPin *)calloc(1, sizeof(*p));
    HANDLE writer = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    int ok = p && writer != INVALID_HANDLE_VALUE
        && WriteFile(writer, bytes, (DWORD)length, &received, NULL) && received == length && FlushFileBuffers(writer);
    if (writer != INVALID_HANDLE_VALUE) CloseHandle(writer);
    if (ok) ok = cm_windows_pin(p, path) && p->size.QuadPart == (LONGLONG)length;
    BYTE buffer[16384];
    size_t offset = 0;
    while (ok && offset < length) {
        DWORD wanted = (DWORD)((length - offset) < sizeof(buffer) ? length - offset : sizeof(buffer));
        ok = ReadFile(p->file, buffer, wanted, &received, NULL) && received == wanted
            && !memcmp(buffer, bytes + offset, received);
        offset += received;
    }
    LARGE_INTEGER zero = {0};
    if (ok) ok = SetFilePointerEx(p->file, zero, NULL, FILE_BEGIN);
    if (ok) {
        wcscpy_s(p->temporary_directory, 4096, directory);
        return p;
    }
    DWORD error = GetLastError();
    if (p) { cm_windows_unpin(p); free(p); }
    DeleteFileW(path);
    RemoveDirectoryW(directory);
    SetLastError(error ? error : ERROR_INVALID_DATA);
    return NULL;
}

void cm_windows_pin_free(CmWindowsPin *p) {
    cm_windows_unpin(p);
    if (p->temporary_directory[0]) {
        DeleteFileW(p->path);
        RemoveDirectoryW(p->temporary_directory);
    }
    free(p);
}

HANDLE cm_windows_pin_duplicate(const CmWindowsPin *p) {
    HANDLE file = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), p->file, GetCurrentProcess(), &file, 0, FALSE, DUPLICATE_SAME_ACCESS)) return NULL;
    return file;
}

const wchar_t *cm_windows_pin_path(const CmWindowsPin *p) { return p->path; }

HMODULE cm_windows_pin_load(const CmWindowsPin *p, const wchar_t *dependencies) {
    if (cm_windows_system_dependencies(dependencies) < 0) { SetLastError(ERROR_BAD_EXE_FORMAT); return NULL; }
    HANDLE current = CreateFileW(p->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    FILE_ID_INFO id;
    LARGE_INTEGER size;
    int same = current != INVALID_HANDLE_VALUE
        && GetFileInformationByHandleEx(current, FileIdInfo, &id, sizeof(id)) && GetFileSizeEx(current, &size)
        && !memcmp(&id, &p->id, sizeof(id)) && size.QuadPart == p->size.QuadPart;
    if (current != INVALID_HANDLE_VALUE) CloseHandle(current);
    if (!same) { SetLastError(ERROR_INVALID_DATA); return NULL; }
    HMODULE module = LoadLibraryExW(p->path, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module && cm_windows_system_dependencies(dependencies) < 0) {
        /* A constructor can publish pointers even when the post-load guard fails. */
        SetLastError(ERROR_BAD_EXE_FORMAT); return NULL;
    }
    return module;
}
