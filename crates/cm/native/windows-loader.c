#include "windows-loader.h"
#include <bcrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

static int cm_windows_pin_limit(CmWindowsPin *p, const wchar_t *name, size_t limit) {
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
        || p->size.QuadPart < 1 || p->size.QuadPart > (LONGLONG)limit) {
        SetLastError(ERROR_INVALID_DATA); return 0;
    }
    wchar_t final[4096];
    length = GetFinalPathNameByHandleW(p->file, final, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!length || length >= 4096 || wcsncmp(final, L"\\\\?\\", 4)
        || _wcsicmp(final + 4, p->path)) { SetLastError(ERROR_INVALID_NAME); return 0; }
    return 1;
}

int cm_windows_pin(CmWindowsPin *p, const wchar_t *name) {
    return cm_windows_pin_limit(p, name, 32 * 1024 * 1024);
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
    const size_t limits[] = {64 * 1024 * 1024, 128 * 1024 * 1024, 2 * 1024 * 1024, 32 * 1024 * 1024};
    if (!bytes || !length || kind >= 4 || length > limits[kind]) {
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
    if (ok) ok = cm_windows_pin_limit(p, path, limits[kind]) && p->size.QuadPart == (LONGLONG)length;
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
    if (!p) return;
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

int cm_windows_file_information(const CmWindowsPin *p, CmWindowsFileInformation *out) {
    BY_HANDLE_FILE_INFORMATION standard;
    FILE_ID_INFO id;
    FILE_BASIC_INFO basic;
    FILE_STANDARD_INFO size;
    if (GetFileType(p->file) != FILE_TYPE_DISK
        || !GetFileInformationByHandle(p->file, &standard)
        || !GetFileInformationByHandleEx(p->file, FileIdInfo, &id, sizeof(id))
        || !GetFileInformationByHandleEx(p->file, FileBasicInfo, &basic, sizeof(basic))
        || !GetFileInformationByHandleEx(p->file, FileStandardInfo, &size, sizeof(size))) return 0;
    if (standard.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        SetLastError(ERROR_REPARSE_TAG_INVALID); return 0;
    }
    out->volume = id.VolumeSerialNumber;
    memcpy(out->id, id.FileId.Identifier, sizeof(out->id));
    out->size = size.EndOfFile.QuadPart;
    out->modified = basic.LastWriteTime.QuadPart;
    out->changed = basic.ChangeTime.QuadPart;
    out->links = standard.nNumberOfLinks;
    out->attributes = standard.dwFileAttributes;
    return 1;
}

static CmWindowsPin *cm_windows_input_finish(CmWindowsPin *p, int directory, int created) {
    CmWindowsFileInformation info;
    wchar_t final[4096];
    DWORD length;
    if (!cm_windows_file_information(p, &info)) goto failed;
    if ((directory >= 0 && !!(info.attributes & FILE_ATTRIBUTE_DIRECTORY) != !!directory)
        || (!(info.attributes & FILE_ATTRIBUTE_DIRECTORY) && info.links != 1)) {
        SetLastError(ERROR_INVALID_DATA); goto failed;
    }
    length = GetFinalPathNameByHandleW(p->file, final, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!length || length >= 4096 || wcsncmp(final, L"\\\\?\\", 4)
        || _wcsicmp(final + 4, p->path)) {
        SetLastError(ERROR_INVALID_NAME); goto failed;
    }
    return p;
failed: {
    DWORD error = GetLastError();
    if (created) {
        FILE_DISPOSITION_INFO disposition = {TRUE};
        SetFileInformationByHandle(p->file, FileDispositionInfo, &disposition, sizeof(disposition));
    }
    cm_windows_pin_free(p);
    SetLastError(error);
    return NULL;
}}

CmWindowsPin *cm_windows_directory_open(const wchar_t *name) {
    CmWindowsPin *p = (CmWindowsPin *)calloc(1, sizeof(*p));
    if (!p) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    p->file = INVALID_HANDLE_VALUE;
    DWORD length = GetFullPathNameW(name, 4096, p->path, NULL);
    if (!length || length >= 4096 || length < 3 || p->path[1] != L':' || p->path[2] != L'\\'
        || _wcsicmp(name, p->path)) { SetLastError(ERROR_INVALID_NAME); goto failed; }
    for (DWORD i = 2; i <= length; ++i) {
        if (p->path[i] != L'\\' && i != length) continue;
        if (i == length && p->path[i - 1] == L'\\') break;
        wchar_t path[4096];
        DWORD end = i == 2 ? 3 : i;
        memcpy(path, p->path, end * sizeof(wchar_t));
        path[end] = 0;
        /* Directory write sharing permits child publication; no delete sharing pins its own name. */
        HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (handle == INVALID_HANDLE_VALUE) goto failed;
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, &info)
            || !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            CloseHandle(handle); SetLastError(ERROR_REPARSE_TAG_INVALID); goto failed;
        }
        if (end == length) { p->file = handle; break; }
        if (p->count == 96) {
            CloseHandle(handle); SetLastError(ERROR_BUFFER_OVERFLOW); goto failed;
        }
        p->parents[p->count++] = handle;
    }
    return cm_windows_input_finish(p, 1, 0);
failed: {
    DWORD error = GetLastError();
    cm_windows_pin_free(p);
    SetLastError(error);
    return NULL;
}}

static int cm_windows_component(const CmWindowsPin *parent, const wchar_t *name) {
    size_t length = wcslen(name);
    if (!length || length > 255 || wcspbrk(name, L"\\/:\"<>?*|") || !wcscmp(name, L".")
        || !wcscmp(name, L"..") || name[length - 1] == L'.' || name[length - 1] == L' '
        || parent->count >= 96) { SetLastError(ERROR_INVALID_NAME); return 0; }
    if (wcslen(parent->path) + length + 2 > 4096) {
        SetLastError(ERROR_BUFFER_OVERFLOW); return 0;
    }
    return 1;
}

static CmWindowsPin *cm_windows_child(const CmWindowsPin *parent, const wchar_t *name, int directory,
    PSECURITY_DESCRIPTOR descriptor, int writable, int mutation, int *created) {
    if (!cm_windows_component(parent, name)) return NULL;
    size_t length = wcslen(name);
    CmWindowsPin *p = (CmWindowsPin *)calloc(1, sizeof(*p));
    if (!p) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    p->file = INVALID_HANDLE_VALUE;
    if (swprintf_s(p->path, 4096, L"%ls%ls%ls", parent->path,
        parent->path[wcslen(parent->path) - 1] == L'\\' ? L"" : L"\\", name) < 0) {
        SetLastError(ERROR_BUFFER_OVERFLOW); goto failed;
    }
    for (size_t i = 0; i <= parent->count; ++i) {
        HANDLE original = i == parent->count ? parent->file : parent->parents[i];
        if (!DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(), &p->parents[p->count],
            0, FALSE, DUPLICATE_SAME_ACCESS)) goto failed;
        ++p->count;
    }
    typedef NTSTATUS (NTAPI *OpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
        PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    typedef ULONG (NTAPI *DosError)(NTSTATUS);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll || !cm_windows_system_module(ntdll)) { SetLastError(ERROR_BAD_EXE_FORMAT); goto failed; }
    OpenFile open_file = (OpenFile)(void *)GetProcAddress(ntdll, "NtCreateFile");
    DosError dos_error = (DosError)(void *)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (!open_file || !dos_error) { SetLastError(ERROR_PROC_NOT_FOUND); goto failed; }
    UNICODE_STRING relative = {(USHORT)(length * sizeof(wchar_t)), (USHORT)(length * sizeof(wchar_t)), (PWSTR)name};
    OBJECT_ATTRIBUTES attributes = {sizeof(attributes), parent->file, &relative, 0x40, descriptor, NULL};
    IO_STATUS_BLOCK status;
    ACCESS_MASK access = directory
        ? FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
        : FILE_GENERIC_READ;
    if (descriptor) access |= FILE_GENERIC_WRITE | WRITE_DAC | (directory ? 0 : DELETE);
    if (writable) access |= FILE_GENERIC_WRITE;
    ULONG options = 0x00200000 | 0x20 | (directory ? 0 : 0x40) | (descriptor ? 2 : 0);
    if (directory && descriptor) {
        /* OBJ_DONT_REPARSE rejects redirects; use only documented FILE_DIRECTORY_FILE options. */
        attributes.Attributes |= 0x1000;
        options = 1 | 2 | 0x20;
    }
    if (mutation) {
        access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE | DELETE;
        attributes.Attributes |= 0x1000;
        options = 0x20;
    }
    NTSTATUS result = open_file(&p->file, access, &attributes, &status, NULL, 0,
        FILE_SHARE_READ | ((!mutation && (directory || writable)) ? FILE_SHARE_WRITE : 0), descriptor ? 2 : 1,
        options, NULL, 0);
    if (result < 0) { SetLastError(dos_error(result)); goto failed; }
    if (created && descriptor) *created = 1;
    return cm_windows_input_finish(p, directory, descriptor != NULL && !directory);
failed: {
    DWORD error = GetLastError();
    cm_windows_pin_free(p);
    SetLastError(error);
    return NULL;
}}

CmWindowsPin *cm_windows_child_open(const CmWindowsPin *parent, const wchar_t *name, int directory) {
    return cm_windows_child(parent, name, directory, NULL, 0, 0, NULL);
}

static TOKEN_USER *cm_windows_user(void) {
    HANDLE token = NULL;
    DWORD length = 0;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)
        && (GetLastError() != ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)))
        return NULL;
    if (GetTokenInformation(token, TokenUser, NULL, 0, &length)
        || GetLastError() != ERROR_INSUFFICIENT_BUFFER || length < sizeof(TOKEN_USER) || length > 65536) {
        CloseHandle(token); SetLastError(ERROR_INVALID_DATA); return NULL;
    }
    TOKEN_USER *user = (TOKEN_USER *)malloc(length);
    if (!user) { CloseHandle(token); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    int ok = GetTokenInformation(token, TokenUser, user, length, &length);
    if (ok && !IsValidSid(user->User.Sid)) { SetLastError(ERROR_INVALID_SID); ok = 0; }
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(token);
    if (!ok) { free(user); user = NULL; }
    SetLastError(error);
    return user;
}

static int cm_windows_private_descriptor(PSECURITY_DESCRIPTOR descriptor, PSID user) {
    /* Managed objects must not inherit grants from a public parent. */
    PSID owner = NULL;
    PACL dacl = NULL;
    BOOL present, defaulted;
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD revision;
    if (!IsValidSecurityDescriptor(descriptor)
        || !GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) || !owner || !IsValidSid(owner)
        || !EqualSid(owner, user)
        || !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present || !dacl
        || !IsValidAcl(dacl) || !dacl->AceCount
        || !GetSecurityDescriptorControl(descriptor, &control, &revision) || !(control & SE_DACL_PROTECTED))
        goto rejected;
    for (DWORD index = 0; index < dacl->AceCount; ++index) {
        ACCESS_ALLOWED_ACE *ace = NULL;
        if (!GetAce(dacl, index, (void **)&ace) || ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE
            || (ace->Header.AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | NO_PROPAGATE_INHERIT_ACE))
            || ace->Header.AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8)
            goto rejected;
        SID *sid = (SID *)&ace->SidStart;
        if (sid->SubAuthorityCount > SID_MAX_SUB_AUTHORITIES
            || GetSidLengthRequired(sid->SubAuthorityCount) > ace->Header.AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart)
            || !IsValidSid(sid) || !EqualSid(sid, user))
            goto rejected;
    }
    return 1;
rejected:
    SetLastError(ERROR_ACCESS_DENIED);
    return 0;
}

static PSECURITY_DESCRIPTOR cm_windows_private_security(const CmWindowsPin *p) {
    TOKEN_USER *user = cm_windows_user();
    if (!user) return NULL;
    DWORD length = 0;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    int ok = 0;
    const SECURITY_INFORMATION requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    if (GetKernelObjectSecurity(p->file, requested, NULL, 0, &length)
        || GetLastError() != ERROR_INSUFFICIENT_BUFFER || length < SECURITY_DESCRIPTOR_MIN_LENGTH || length > 65536) {
        SetLastError(ERROR_INVALID_DATA); goto done;
    }
    descriptor = (PSECURITY_DESCRIPTOR)malloc(length);
    if (!descriptor) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); goto done; }
    if (!GetKernelObjectSecurity(p->file, requested, descriptor, length, &length)) goto done;
    ok = cm_windows_private_descriptor(descriptor, user->User.Sid);
done: {
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok) { free(descriptor); descriptor = NULL; }
    free(user);
    SetLastError(error);
    return descriptor;
}}

int cm_windows_private_check(const CmWindowsPin *p) {
    CmWindowsFileInformation info;
    if (!cm_windows_file_information(p, &info)) return 0;
    if (!(info.attributes & FILE_ATTRIBUTE_DIRECTORY) && info.links != 1) {
        SetLastError(ERROR_INVALID_DATA); return 0;
    }
    PSECURITY_DESCRIPTOR descriptor = cm_windows_private_security(p);
    if (!descriptor) return 0;
    free(descriptor);
    return 1;
}

static int cm_windows_same_information(const CmWindowsFileInformation *a, const CmWindowsFileInformation *b) {
    return a->volume == b->volume && !memcmp(a->id, b->id, sizeof(a->id)) && a->size == b->size
        && a->modified == b->modified && a->changed == b->changed && a->links == b->links
        && a->attributes == b->attributes;
}

int cm_windows_private_metadata(const CmWindowsPin *p, DWORD *attributes, wchar_t *text, size_t capacity) {
    CmWindowsFileInformation before, after;
    const DWORD supported = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
        | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL
        | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
    if (!capacity || capacity > 4096 || !text || !attributes) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!cm_windows_private_check(p) || !cm_windows_file_information(p, &before)) return 0;
    if (before.attributes & ~supported) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    PSECURITY_DESCRIPTOR descriptor = cm_windows_private_security(p);
    if (!descriptor) return 0;
    wchar_t *serialized = NULL;
    ULONG length = 0;
    int ok = 0;
    /* Normalize OS auto-inheritance bookkeeping only after validating the protected, explicit DACL. */
    if (!SetSecurityDescriptorControl(descriptor, SE_DACL_AUTO_INHERITED, 0)) goto done;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &serialized, &length)) goto done;
    size_t used = wcsnlen_s(serialized, length < capacity ? length : capacity);
    if (!used || used >= capacity || used >= length) {
        SetLastError(ERROR_BUFFER_OVERFLOW); goto done;
    }
    if (!cm_windows_file_information(p, &after) || !cm_windows_private_check(p)) goto done;
    if (!cm_windows_same_information(&before, &after)) { SetLastError(ERROR_INVALID_DATA); goto done; }
    memcpy(text, serialized, (used + 1) * sizeof(wchar_t));
    *attributes = before.attributes;
    ok = 1;
done: {
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (serialized) LocalFree(serialized);
    free(descriptor);
    SetLastError(error);
    return ok;
}}

int cm_windows_private_copy_metadata(const CmWindowsPin *target, const CmWindowsPin *source) {
    wchar_t expected[4096], current[4096];
    DWORD attributes, actual;
    CmWindowsFileInformation before, after, destination;
    if (!cm_windows_file_information(source, &before)
        || !cm_windows_private_metadata(source, &attributes, expected, 4096)
        || !cm_windows_private_check(target) || !cm_windows_file_information(target, &destination)) return -1;
    if (!!(before.attributes & FILE_ATTRIBUTE_DIRECTORY) != !!(destination.attributes & FILE_ATTRIBUTE_DIRECTORY)
        || (before.volume == destination.volume && !memcmp(before.id, destination.id, sizeof(before.id)))) {
        SetLastError(ERROR_INVALID_DATA); return -2;
    }
    PSECURITY_DESCRIPTOR descriptor = cm_windows_private_security(source);
    if (!descriptor) return -3;
    PACL dacl = NULL;
    BOOL present, defaulted;
    int result = -4;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present || !dacl) {
        SetLastError(ERROR_INVALID_ACL); goto done;
    }
    result = -5;
    DWORD security_result = SetSecurityInfo(target->file, SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL);
    if (security_result != ERROR_SUCCESS) { SetLastError(security_result); goto done; }
    FILE_BASIC_INFO basic = {0};
    basic.FileAttributes = attributes;
    result = -6;
    if (!SetFileInformationByHandle(target->file, FileBasicInfo, &basic, sizeof(basic))
        || !FlushFileBuffers(target->file)) goto done;
    result = -7;
    if (!cm_windows_private_metadata(source, &actual, current, 4096)) goto done;
    result = -8;
    if (attributes != actual || wcscmp(expected, current)
        || !cm_windows_file_information(source, &after) || !cm_windows_same_information(&before, &after)) {
        SetLastError(ERROR_INVALID_DATA); goto done;
    }
    result = -9;
    if (!cm_windows_private_metadata(target, &actual, current, 4096)) goto done;
    result = -10;
    if (attributes != actual || wcscmp(expected, current)) { SetLastError(ERROR_INVALID_DATA); goto done; }
    result = 1;
done: {
    DWORD error = result == 1 ? ERROR_SUCCESS : GetLastError();
    free(descriptor);
    SetLastError(error);
    return result;
}}

static int cm_windows_storage_directory(const CmWindowsPin *parent) {
    CmWindowsFileInformation info;
    wchar_t filesystem[16];
    DWORD flags = 0;
    if (!cm_windows_file_information(parent, &info)) return 0;
    if (!(info.attributes & FILE_ATTRIBUTE_DIRECTORY)) { SetLastError(ERROR_DIRECTORY); return 0; }
    if (!GetVolumeInformationByHandleW(parent->file, NULL, 0, NULL, NULL, &flags, filesystem, 16)) return 0;
    /* shortcut: private writes require NTFS; qualify other filesystems before expanding support. */
    if (_wcsicmp(filesystem, L"NTFS") || !(flags & FILE_PERSISTENT_ACLS)) {
        SetLastError(ERROR_NOT_SUPPORTED); return 0;
    }
    return 1;
}

static int cm_windows_private_parent(const CmWindowsPin *parent) {
    return cm_windows_private_check(parent) && cm_windows_storage_directory(parent);
}

CmWindowsPin *cm_windows_private_create(const CmWindowsPin *parent, const wchar_t *name) {
    if (!cm_windows_private_parent(parent)) return NULL;
    typedef NTSTATUS (NTAPI *QueryFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    typedef ULONG (NTAPI *DosError)(NTSTATUS);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll || !cm_windows_system_module(ntdll)) { SetLastError(ERROR_BAD_EXE_FORMAT); return NULL; }
    QueryFile query_file = (QueryFile)(void *)GetProcAddress(ntdll, "NtQueryInformationFile");
    DosError dos_error = (DosError)(void *)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (!query_file || !dos_error) { SetLastError(ERROR_PROC_NOT_FOUND); return NULL; }
    TOKEN_USER *user = cm_windows_user();
    if (!user) return NULL;
    CmWindowsPin *p = NULL;
    int ok = 0;
    union { ACL alignment; BYTE bytes[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE]; } acl;
    SECURITY_DESCRIPTOR descriptor;
    if (!InitializeAcl((PACL)&acl, sizeof(acl), ACL_REVISION)
        || !AddAccessAllowedAceEx((PACL)&acl, ACL_REVISION, 0, FILE_ALL_ACCESS, user->User.Sid)
        || !InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION)
        || !SetSecurityDescriptorOwner(&descriptor, user->User.Sid, FALSE)
        || !SetSecurityDescriptorDacl(&descriptor, TRUE, (PACL)&acl, FALSE)
        || !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        || !cm_windows_private_descriptor(&descriptor, user->User.Sid)) goto done;
    p = cm_windows_child(parent, name, 0, &descriptor, 0, 0, NULL);
    if (!p || !cm_windows_private_check(p)) goto done;
    ULONG mode = 0;
    IO_STATUS_BLOCK status;
    NTSTATUS result = query_file(p->file, &status, &mode, sizeof(mode), (FILE_INFORMATION_CLASS)16);
    if (result < 0) { SetLastError(dos_error(result)); goto done; }
    if (!(mode & 2)) { SetLastError(ERROR_INVALID_DATA); goto done; }
    if (!cm_windows_private_check(parent)) goto done;
    ok = 1;
done: {
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && p) {
        FILE_DISPOSITION_INFO disposition = {TRUE};
        SetFileInformationByHandle(p->file, FileDispositionInfo, &disposition, sizeof(disposition));
        cm_windows_pin_free(p);
        p = NULL;
    }
    free(user);
    SetLastError(error);
    return p;
}}

int cm_windows_private_write(const CmWindowsPin *parent, const wchar_t *name,
    const unsigned char *bytes, size_t length) {
    if (length && !bytes) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    CmWindowsPin *p = cm_windows_private_create(parent, name);
    if (!p) return 0;
    int ok = 0;
    for (size_t offset = 0; offset < length;) {
        DWORD amount = length - offset > 16384 ? 16384 : (DWORD)(length - offset), received = 0;
        if (!WriteFile(p->file, bytes + offset, amount, &received, NULL)) goto done;
        if (!received || received > amount) { SetLastError(ERROR_WRITE_FAULT); goto done; }
        offset += received;
    }
    if (!FlushFileBuffers(p->file) || !cm_windows_private_check(p) || !cm_windows_private_check(parent)) goto done;
    ok = 1;
done: {
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (p) {
        if (!ok) {
            FILE_DISPOSITION_INFO disposition = {TRUE};
            SetFileInformationByHandle(p->file, FileDispositionInfo, &disposition, sizeof(disposition));
        }
        cm_windows_pin_free(p);
    }
    SetLastError(error);
    return ok;
}}

static CmWindowsPin *cm_windows_owned_directory(const CmWindowsPin *parent, const wchar_t *name,
    int create_only, int private_parent, int *created) {
    if (!(private_parent ? cm_windows_private_parent(parent) : cm_windows_storage_directory(parent))) return NULL;
    TOKEN_USER *user = cm_windows_user();
    if (!user) return NULL;
    CmWindowsPin *p = NULL;
    union { ACL alignment; BYTE bytes[sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE]; } acl;
    SECURITY_DESCRIPTOR descriptor;
    if (!InitializeAcl((PACL)&acl, sizeof(acl), ACL_REVISION)
        || !AddAccessAllowedAceEx((PACL)&acl, ACL_REVISION, 0, FILE_ALL_ACCESS, user->User.Sid)
        || !InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION)
        || !SetSecurityDescriptorOwner(&descriptor, user->User.Sid, FALSE)
        || !SetSecurityDescriptorDacl(&descriptor, TRUE, (PACL)&acl, FALSE)
        || !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        || !cm_windows_private_descriptor(&descriptor, user->User.Sid)) goto done;
    p = cm_windows_child(parent, name, 1, &descriptor, 0, 0, created);
    if (!p && !create_only && (GetLastError() == ERROR_ALREADY_EXISTS || GetLastError() == ERROR_FILE_EXISTS))
        p = cm_windows_child(parent, name, 1, NULL, 0, 0, NULL);
    if (p && (!cm_windows_private_check(p)
        || !(private_parent ? cm_windows_private_parent(parent) : cm_windows_storage_directory(parent)))) {
        DWORD error = GetLastError();
        cm_windows_pin_free(p);
        p = NULL;
        SetLastError(error);
    }
done: {
    DWORD error = p ? ERROR_SUCCESS : GetLastError();
    free(user);
    SetLastError(error);
    return p;
}}

CmWindowsPin *cm_windows_private_directory(const CmWindowsPin *parent, const wchar_t *name, int create_only) {
    return cm_windows_owned_directory(parent, name, create_only, 1, NULL);
}

static int cm_windows_directory_sync(const CmWindowsPin *directory, int private_directory) {
    if (!(private_directory ? cm_windows_private_parent(directory) : cm_windows_storage_directory(directory))) return 0;
    if (FlushFileBuffers(directory->file))
        return private_directory ? cm_windows_private_parent(directory) : cm_windows_storage_directory(directory);
    if (GetLastError() != ERROR_ACCESS_DENIED) return 0;
    HANDLE handle = CreateFileW(directory->path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE) return 0;
    CmWindowsPin current = {0};
    CmWindowsFileInformation before, now;
    current.file = handle;
    int ok = 0;
    if (!cm_windows_file_information(directory, &before) || !cm_windows_file_information(&current, &now)) goto done;
    if (before.volume != now.volume || memcmp(before.id, now.id, sizeof(before.id))) {
        SetLastError(ERROR_INVALID_DATA); goto done;
    }
    if (!(private_directory ? cm_windows_private_parent(&current) : cm_windows_storage_directory(&current))
        || !FlushFileBuffers(handle)
        || !(private_directory ? cm_windows_private_parent(directory) : cm_windows_storage_directory(directory))
        || !(private_directory ? cm_windows_private_parent(&current) : cm_windows_storage_directory(&current))) goto done;
    ok = 1;
done: {
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(handle);
    SetLastError(error);
    return ok;
}}

int cm_windows_private_sync(const CmWindowsPin *directory) {
    return cm_windows_directory_sync(directory, 1);
}

CmWindowsPin *cm_windows_home_create(const CmWindowsPin *parent, const wchar_t *name, int *created) {
    if (!created) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    *created = 0;
    CmWindowsPin *p = cm_windows_owned_directory(parent, name, 1, 0, created);
    if (p && !cm_windows_directory_sync(parent, 0)) {
        DWORD error = GetLastError();
        cm_windows_pin_free(p);
        p = NULL;
        SetLastError(error);
    }
    return p;
}

static int cm_windows_private_rename(const CmWindowsPin *parent, const wchar_t *source,
    const wchar_t *target, const CmWindowsFileInformation *expected) {
    if (!cm_windows_private_parent(parent) || !cm_windows_component(parent, target)) return -1;
    CmWindowsPin *p = cm_windows_child(parent, source, -1, NULL, 0, 1, NULL);
    if (!p) return -3;
    CmWindowsPin *old = NULL;
    int result = -4;
    if (!cm_windows_private_check(p) || !cm_windows_private_check(parent)) goto done;
    result = -5;
    int comparison = CompareStringOrdinal(source, -1, target, -1, TRUE);
    if (!comparison) goto done;
    if (comparison == CSTR_EQUAL) {
        if (!expected) result = 0;
        else SetLastError(ERROR_INVALID_NAME);
        goto done;
    }
    if (expected) {
        CmWindowsFileInformation info;
        if (!cm_windows_file_information(p, &info)) goto done;
        if (info.attributes & FILE_ATTRIBUTE_DIRECTORY) { SetLastError(ERROR_DIRECTORY); goto done; }
        old = cm_windows_child(parent, target, 0, NULL, 0, 1, NULL);
        if (!old || !cm_windows_private_check(old) || !cm_windows_file_information(old, &info)) goto done;
        if (info.volume != expected->volume || memcmp(info.id, expected->id, sizeof(info.id))) {
            SetLastError(ERROR_INVALID_DATA); goto done;
        }
        /* Normal replacement needs our validation handle closed; outside pins remain authoritative. */
        cm_windows_pin_free(old);
        old = NULL;
    }
    size_t length = wcslen(target);
    union {
        FILE_RENAME_INFO alignment;
        BYTE bytes[sizeof(FILE_RENAME_INFO) + 255 * sizeof(wchar_t)];
    } buffer;
    ZeroMemory(&buffer, sizeof(buffer));
    FILE_RENAME_INFO *rename = (FILE_RENAME_INFO *)buffer.bytes;
    rename->ReplaceIfExists = expected != NULL;
    rename->RootDirectory = parent->file;
    rename->FileNameLength = (DWORD)(length * sizeof(wchar_t));
    memcpy(rename->FileName, target, length * sizeof(wchar_t));
    if (swprintf_s(p->path, 4096, L"%ls%ls%ls", parent->path,
        parent->path[wcslen(parent->path) - 1] == L'\\' ? L"" : L"\\", target) < 0) {
        SetLastError(ERROR_BUFFER_OVERFLOW); goto done;
    }
    result = -6;
    typedef NTSTATUS (NTAPI *RenameFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    typedef ULONG (NTAPI *DosError)(NTSTATUS);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll || !cm_windows_system_module(ntdll)) { SetLastError(ERROR_BAD_EXE_FORMAT); goto done; }
    RenameFile rename_file = (RenameFile)(void *)GetProcAddress(ntdll, "NtSetInformationFile");
    DosError dos_error = (DosError)(void *)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (!rename_file || !dos_error) { SetLastError(ERROR_PROC_NOT_FOUND); goto done; }
    IO_STATUS_BLOCK status;
    /* FileRenameInformation resolves the target against the retained parent handle. */
    NTSTATUS renamed = rename_file(p->file, &status, rename,
        (ULONG)(sizeof(FILE_RENAME_INFO) + length * sizeof(wchar_t)), (FILE_INFORMATION_CLASS)10);
    if (renamed < 0) {
        DWORD error = dos_error(renamed);
        if (!expected && (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS)) result = 0;
        SetLastError(error);
        goto done;
    }
    /* A later verification failure must not be reported as an uncommitted rename. */
    result = -2;
    p = cm_windows_input_finish(p, -1, 0);
    if (!p || !cm_windows_private_check(p) || !cm_windows_private_check(parent)) goto done;
    result = 1;
done: {
    DWORD error = result == 1 ? ERROR_SUCCESS : GetLastError();
    cm_windows_pin_free(old);
    cm_windows_pin_free(p);
    SetLastError(error);
    return result;
}}

int cm_windows_private_publish(const CmWindowsPin *parent, const wchar_t *source, const wchar_t *target) {
    return cm_windows_private_rename(parent, source, target, NULL);
}

int cm_windows_private_replace(const CmWindowsPin *parent, const wchar_t *source, const wchar_t *target,
    ULONGLONG volume, const BYTE id[16]) {
    if (!id) { SetLastError(ERROR_INVALID_PARAMETER); return -1; }
    CmWindowsFileInformation expected = {0};
    expected.volume = volume;
    memcpy(expected.id, id, sizeof(expected.id));
    return cm_windows_private_rename(parent, source, target, &expected);
}

int cm_windows_private_remove(const CmWindowsPin *parent, const wchar_t *name,
    ULONGLONG volume, const BYTE id[16], int directory) {
    if (!cm_windows_private_parent(parent)) return -1;
    CmWindowsPin *p = cm_windows_child(parent, name, directory, NULL, 0, 1, NULL);
    if (!p) return -3;
    int result = -4;
    CmWindowsFileInformation info;
    if (!cm_windows_private_check(p) || !cm_windows_private_check(parent)
        || !cm_windows_file_information(p, &info)) goto done;
    result = -5;
    if (info.volume != volume || memcmp(info.id, id, sizeof(info.id))) {
        SetLastError(ERROR_INVALID_DATA); goto done;
    }
    result = -6;
    if (info.attributes & FILE_ATTRIBUTE_READONLY) {
        typedef NTSTATUS (NTAPI *SetInformation)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
        typedef ULONG (NTAPI *DosError)(NTSTATUS);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll || !cm_windows_system_module(ntdll)) { SetLastError(ERROR_BAD_EXE_FORMAT); goto done; }
        SetInformation set_information = (SetInformation)(void *)GetProcAddress(ntdll, "NtSetInformationFile");
        DosError dos_error = (DosError)(void *)GetProcAddress(ntdll, "RtlNtStatusToDosError");
        if (!set_information || !dos_error) { SetLastError(ERROR_PROC_NOT_FOUND); goto done; }
        /* Ignore readonly only; retain image-section checks and normal, non-POSIX deletion. */
        ULONG flags = 0x15;
        IO_STATUS_BLOCK status;
        NTSTATUS disposition_status = set_information(p->file, &status, &flags, sizeof(flags), (FILE_INFORMATION_CLASS)64);
        if (disposition_status < 0) { SetLastError(dos_error(disposition_status)); goto done; }
    } else {
        FILE_DISPOSITION_INFO disposition = {TRUE};
        if (!SetFileInformationByHandle(p->file, FileDispositionInfo, &disposition, sizeof(disposition))) goto done;
    }
    /* Close only our deletion handle; unrelated retained pins must have prevented this open. */
    cm_windows_pin_free(p);
    p = NULL;
    result = cm_windows_private_check(parent) ? 1 : -2;
done: {
    DWORD error = result == 1 ? ERROR_SUCCESS : GetLastError();
    cm_windows_pin_free(p);
    SetLastError(error);
    return result;
}}

CmWindowsPin *cm_windows_lock_open(const CmWindowsPin *parent, const wchar_t *name, int create) {
    if (!cm_windows_private_check(parent)) return NULL;
    CmWindowsPin *p = cm_windows_child(parent, name, 0, NULL, 1, 0, NULL);
    if (!p && create && GetLastError() == ERROR_FILE_NOT_FOUND) {
        if (!cm_windows_private_write(parent, name, NULL, 0)) {
            DWORD error = GetLastError();
            if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS) return NULL;
        }
        p = cm_windows_child(parent, name, 0, NULL, 1, 0, NULL);
    }
    if (!p) return NULL;
    if (!cm_windows_private_check(p) || !cm_windows_private_check(parent)) {
        DWORD error = GetLastError();
        cm_windows_pin_free(p);
        SetLastError(error);
        return NULL;
    }
    return p;
}

CmWindowsProcess *cm_windows_verifier_spawn(const wchar_t *program, wchar_t *command,
    const wchar_t *environment, HANDLE *output, HANDLE *diagnostics) {
    CmWindowsProcess *p = (CmWindowsProcess *)calloc(1, sizeof(*p));
    if (!p) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
    STARTUPINFOEXW startup = {0};
    PROCESS_INFORMATION child = {0};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    HANDLE read_output = NULL, read_error = NULL, inherited[3] = {NULL, NULL, NULL};
    SIZE_T size = 0;
    BOOL initialized = FALSE, ok = FALSE;
    p->job = CreateJobObjectW(NULL, NULL);
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!p->job || !SetInformationJobObject(p->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))
        || !CreatePipe(&read_output, &inherited[1], &security, 0)
        || !CreatePipe(&read_error, &inherited[2], &security, 0)
        || !SetHandleInformation(read_output, HANDLE_FLAG_INHERIT, 0)
        || !SetHandleInformation(read_error, HANDLE_FLAG_INHERIT, 0)) goto done;
    inherited[0] = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (inherited[0] == INVALID_HANDLE_VALUE) goto done;
    InitializeProcThreadAttributeList(NULL, 2, 0, &size);
    if (!size) goto done;
    startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(size);
    if (!startup.lpAttributeList) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); goto done; }
    if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 2, 0, &size)) goto done;
    initialized = TRUE;
    /* Assign atomically at creation; a running child must never precede its job. */
    if (!UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            &p->job, sizeof(p->job), NULL, NULL)
        || !UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), NULL, NULL)) goto done;
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inherited[0];
    startup.StartupInfo.hStdOutput = inherited[1];
    startup.StartupInfo.hStdError = inherited[2];
    if (!CreateProcessW(program, command, NULL, NULL, TRUE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            (void *)environment, NULL, &startup.StartupInfo, &child)) goto done;
    p->process = child.hProcess;
    CloseHandle(child.hThread);
    *output = read_output; *diagnostics = read_error;
    read_output = read_error = NULL;
    ok = TRUE;
done: {
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    for (size_t i = 0; i < 3; ++i)
        if (inherited[i] && inherited[i] != INVALID_HANDLE_VALUE) CloseHandle(inherited[i]);
    if (read_output) CloseHandle(read_output);
    if (read_error) CloseHandle(read_error);
    if (!ok) { cm_windows_verifier_free(p); p = NULL; }
    SetLastError(error);
    return p;
}}

int cm_windows_verifier_poll(const CmWindowsProcess *p, DWORD *code) {
    DWORD status = WaitForSingleObject(p->process, 0);
    if (status == WAIT_TIMEOUT) return 0;
    if (status != WAIT_OBJECT_0 || !GetExitCodeProcess(p->process, code)) return -1;
    return 1;
}

void cm_windows_verifier_stop(CmWindowsProcess *p) {
    if (p->job) {
        TerminateJobObject(p->job, 1);
        CloseHandle(p->job);
        p->job = NULL;
    }
}

void cm_windows_verifier_free(CmWindowsProcess *p) {
    if (!p) return;
    cm_windows_verifier_stop(p);
    if (p->process) CloseHandle(p->process);
    free(p);
}
