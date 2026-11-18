#ifndef CM_WINDOWS_LOADER_H
#define CM_WINDOWS_LOADER_H
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>

typedef struct {
    HANDLE parents[96], file;
    size_t count;
    BOOL file_attempted;
    FILE_ID_INFO id;
    LARGE_INTEGER size;
    wchar_t path[4096], temporary_directory[4096];
} CmWindowsPin;

typedef struct {
    ULONGLONG volume;
    BYTE id[16];
    LONGLONG size, modified, changed;
    DWORD links, attributes;
} CmWindowsFileInformation;

int cm_windows_pin(CmWindowsPin *pin, const wchar_t *path);
void cm_windows_unpin(CmWindowsPin *pin);
int cm_windows_sha256(HANDLE file, const wchar_t *expected);
int cm_windows_system_module(HMODULE module);
int cm_windows_system_dependencies(const wchar_t *csv);
CmWindowsPin *cm_windows_pin_open(const wchar_t *path, const wchar_t *expected);
CmWindowsPin *cm_windows_pin_copy(const unsigned char *bytes, size_t length, unsigned kind);
void cm_windows_pin_free(CmWindowsPin *pin);
HANDLE cm_windows_pin_duplicate(const CmWindowsPin *pin);
const wchar_t *cm_windows_pin_path(const CmWindowsPin *pin);
HMODULE cm_windows_pin_load(const CmWindowsPin *pin, const wchar_t *dependencies);
CmWindowsPin *cm_windows_directory_open(const wchar_t *path);
CmWindowsPin *cm_windows_child_open(const CmWindowsPin *parent, const wchar_t *name, int directory);
int cm_windows_file_information(const CmWindowsPin *pin, CmWindowsFileInformation *information);
int cm_windows_private_check(const CmWindowsPin *pin);
int cm_windows_private_write(const CmWindowsPin *parent, const wchar_t *name,
    const unsigned char *bytes, size_t length);
#endif
