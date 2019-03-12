
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <windows.h>

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  
#define ZwCurrentProcess() NtCurrentProcess()  

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_SEQUENTIAL_ONLY 0x00000004L

typedef LONG NTSTATUS, *PNTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
}

//----------------------------------------------------------

typedef ULONG (_cdecl *DbgPrint_t)(PCHAR Format, ...);

typedef
NTSTATUS
(NTAPI *ZwOpenFile_t)(
             __out PHANDLE FileHandle,
             __in ACCESS_MASK DesiredAccess,
             __in POBJECT_ATTRIBUTES ObjectAttributes,
             __out PIO_STATUS_BLOCK IoStatusBlock,
             __in ULONG ShareAccess,
             __in ULONG OpenOptions
             );

typedef
NTSTATUS
(NTAPI *ZwClose_t)( __in HANDLE Handle );

typedef
NTSTATUS
(NTAPI *ZwCreateSection_t)(
                   __out PHANDLE SectionHandle,
                   __in ACCESS_MASK DesiredAccess,
                   __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
                   __in_opt PLARGE_INTEGER MaximumSize,
                   __in ULONG SectionPageProtection,
                   __in ULONG AllocationAttributes,
                   __in_opt HANDLE FileHandle
                   );

typedef
NTSTATUS
(NTAPI *ZwMapViewOfSection_t)(
                     __in HANDLE SectionHandle,
                     __in HANDLE ProcessHandle,
                     __inout PVOID *BaseAddress,
                     __in ULONG_PTR ZeroBits,
                     __in SIZE_T CommitSize,
                     __inout_opt PLARGE_INTEGER SectionOffset,
                     __inout PSIZE_T ViewSize,
                     __in SECTION_INHERIT InheritDisposition,
                     __in ULONG AllocationType,
                     __in ULONG Win32Protect
                     );

typedef
NTSTATUS
(NTAPI *ZwUnmapViewOfSection_t)(
                       __in HANDLE ProcessHandle,
                       __in_opt PVOID BaseAddress
                       );

//---------------------------------------------
extern DbgPrint_t DbgPrint;
extern ZwOpenFile_t ZwOpenFile;
extern ZwClose_t ZwClose;
extern ZwCreateSection_t ZwCreateSection;
extern ZwMapViewOfSection_t ZwMapViewOfSection;
extern ZwUnmapViewOfSection_t ZwUnmapViewOfSection;
//---------------------------------------------

VOID Init_NTAPI();
PVOID OpenAndMapFile(PUNICODE_STRING pusFilePath, PSIZE_T Size);

#ifdef __cplusplus
};
#endif