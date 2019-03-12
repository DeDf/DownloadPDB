
#include "NTAPI.h"

//---------------------------------------------
DbgPrint_t DbgPrint;
ZwOpenFile_t ZwOpenFile;
ZwClose_t ZwClose;
ZwCreateSection_t ZwCreateSection;
ZwMapViewOfSection_t ZwMapViewOfSection;
ZwUnmapViewOfSection_t ZwUnmapViewOfSection;
//---------------------------------------------

VOID Init_NTAPI()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    //
    DbgPrint = (DbgPrint_t)GetProcAddress(hNtdll, "DbgPrint");
    ZwOpenFile = (ZwOpenFile_t)GetProcAddress(hNtdll, "ZwOpenFile");
    ZwClose = (ZwClose_t)GetProcAddress(hNtdll, "ZwClose");
    ZwCreateSection = (ZwCreateSection_t)GetProcAddress(hNtdll, "ZwCreateSection");
    ZwMapViewOfSection = (ZwMapViewOfSection_t)GetProcAddress(hNtdll, "ZwMapViewOfSection");
    ZwUnmapViewOfSection = (ZwUnmapViewOfSection_t)GetProcAddress(hNtdll, "ZwUnmapViewOfSection");
}

// 用完记得ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);
PVOID OpenAndMapFile(PUNICODE_STRING pusFilePath, PSIZE_T Size)
{
    PVOID MapFileBaseAddress = NULL;
    NTSTATUS status;
    HANDLE  FileHandle = NULL;
    HANDLE  SectionHandle = NULL;
    IO_STATUS_BLOCK IoStatus = { 0 };
    OBJECT_ATTRIBUTES oa = { 0 };

    InitializeObjectAttributes(
        &oa,
        pusFilePath,
        OBJ_CASE_INSENSITIVE,
        0,
        0
        );

    status = ZwOpenFile(&FileHandle,
        FILE_READ_DATA,
        &oa,
        &IoStatus,
        FILE_SHARE_READ,
        FILE_SEQUENTIAL_ONLY);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[NTAPI] ZwOpenFile failed: 0x%x\n", status);
        return NULL;
    }
    oa.ObjectName = 0;

    status = ZwCreateSection(&SectionHandle,
        SECTION_ALL_ACCESS,
        &oa,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        FileHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[NTAPI] ZwCreateSection failed: 0x%x\n", status);
        ZwClose(FileHandle);
        return NULL;
    }

    status = ZwMapViewOfSection(SectionHandle,
        ZwCurrentProcess(),
        &MapFileBaseAddress,
        0,
        0,
        0,
        Size,
        ViewUnmap,
        0,
        PAGE_READONLY);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[NTAPI] ZwMapViewOfSection failed: 0x%x\n", status);
        ZwClose(SectionHandle);
        ZwClose(FileHandle);
        return NULL;
    }

    ZwClose(SectionHandle);
    ZwClose(FileHandle);
    return MapFileBaseAddress;
}