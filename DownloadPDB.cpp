
#include <stdio.h>
#include "NTAPI.h"

#define NB10_SIG	'01BN'
#define RSDS_SIG	'SDSR'

typedef struct _PDB20
{
    DWORD  Signature;
    DWORD  Offset;
    DWORD  SignaturePDB20;
    DWORD  Age;
    BYTE   PdbFileName[1];
} PDB20;

typedef struct _PDB70
{
    DWORD	Signature;
    GUID	guid;
    DWORD	Age;
    BYTE	PdbFileName[1];
} PDB70;

BOOL PeIsRegionValid(PVOID Base, DWORD Size, PVOID Addr, DWORD RegionSize)
{
    return ((PBYTE)Addr >= (PBYTE)Base && ((PBYTE)Addr + RegionSize) <= ((PBYTE)Base + Size));
}

//返回TRUE 但PdbStr为空意思是找过了确实没有PDB
BOOLEAN PeGetPdb(PVOID ImageBase, DWORD ImageSize, PCHAR pchPdbName, GUID *pGuid, PDWORD pAge)
{
    BOOLEAN Result = FALSE;
    PBYTE Base = (PBYTE)ImageBase;
    PIMAGE_DEBUG_DIRECTORY DbgDir;
    PBYTE pPDB;
    ULONG PdbNameSize = 0;

    if (pchPdbName)
        *pchPdbName = 0;

    if (pAge)
        *pAge = 0;

    __try
    {
        do
        {
            PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Base;
            PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);
            PIMAGE_OPTIONAL_HEADER		OptionalHeader;
            PIMAGE_OPTIONAL_HEADER64	OptionalHeader64;
            PIMAGE_OPTIONAL_HEADER32	OptionalHeader32;
            DWORD DbgDirRva = 0;

            //PE解析代码
            OptionalHeader = (PIMAGE_OPTIONAL_HEADER)(Base + DosHeader->e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader));
            if (OptionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)	// PE32+  x64
            {
                OptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)OptionalHeader;
                DbgDirRva = OptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            }
            else	// PE32   x86
            {
                OptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)OptionalHeader;
                DbgDirRva = OptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            }

            DbgDir = (PIMAGE_DEBUG_DIRECTORY)(Base + DbgDirRva);
            if (!DbgDir)
                break;

            Result = TRUE;//到此表示解析正常 能不能找到PDB就看有没有了

            if (!DbgDir->AddressOfRawData || DbgDir->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
                break;

            pPDB = Base + DbgDir->AddressOfRawData;
            if (!PeIsRegionValid(Base, ImageSize, pPDB, sizeof(DWORD)))
                break;

            if (*(DWORD*)pPDB == NB10_SIG) //VC6.0 (GBK)
            {
                if (!PeIsRegionValid(Base, ImageSize, pPDB, sizeof(_PDB20)+MAX_PATH))
                    break;

                if (pAge)
                    *pAge = ((_PDB20*)pPDB)->Age;

                PdbNameSize = strlen((CHAR*)((_PDB20*)pPDB)->PdbFileName);
                if (!PdbNameSize || PdbNameSize >= MAX_PATH)
                    break;

                if (pchPdbName)
                {
                    RtlCopyMemory(pchPdbName, (CHAR*)((_PDB20*)pPDB)->PdbFileName, PdbNameSize);
                    pchPdbName[PdbNameSize] = 0;
                }
            }
            else if (*(DWORD*)pPDB == RSDS_SIG) //VS2003+ (UTF-8)
            {
                if (!PeIsRegionValid(Base, ImageSize, pPDB, sizeof(_PDB70)+MAX_PATH))
                    break;

                if (pAge)
                    *pAge = ((_PDB70*)pPDB)->Age;

                PdbNameSize = strlen((CHAR*)((_PDB70*)pPDB)->PdbFileName);
                if (!PdbNameSize || PdbNameSize >= MAX_PATH)
                    break;

                if (pchPdbName)
                {
                    RtlCopyMemory(pchPdbName, (CHAR*)((_PDB70*)pPDB)->PdbFileName, PdbNameSize);
                    pchPdbName[PdbNameSize] = 0;
                }

                if (pGuid)
                {
                    GUID *p = &((_PDB70*)pPDB)->guid;
                    ULONG i;

                    pGuid->Data1 = p->Data1;
                    pGuid->Data2 = p->Data2;
                    pGuid->Data3 = p->Data3;
                    for(i = 0; i < 8; i++)
                        pGuid->Data4[i] = p->Data4[i];
                }
//                 printf("GUID: %08x %04x %04x %02x%02x%02x%02x%02x%02x%02x%02x\n", p->Data1, p->Data2, p->Data3,
//                     p->Data4[0], p->Data4[1], p->Data4[2], p->Data4[3], p->Data4[4], p->Data4[5], p->Data4[6], p->Data4[7]);
            }
        } while (0);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("EXCEPTION_EXECUTE_HANDLER\n");
        Result = FALSE;
    }

    return Result;
}


void CatStrGUID(CHAR *pstr, struct _GUID *pGuid, unsigned int size)
{
    if ( pstr && pGuid )
    {
        char Dst[0x204];
        sprintf_s(Dst, 0x204, "%08X", pGuid->Data1);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%04X", pGuid->Data2);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%04X", pGuid->Data3);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%02X", pGuid->Data4[0]);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%02X", pGuid->Data4[1]);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%02X", pGuid->Data4[2]);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%02X", pGuid->Data4[3]);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%02X", pGuid->Data4[4]);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%02X", pGuid->Data4[5]);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%02X", pGuid->Data4[6]);
        strcat_s(pstr, size, Dst);
        sprintf_s(Dst, 0x204, "%02X", pGuid->Data4[7]);
        strcat_s(pstr, size, Dst);
    }
}

void CatStrDWORD(CHAR *pstr, int ulVal, unsigned int size)
{
    char Dst[0x204];

    if ( ulVal )
    {
        sprintf_s(Dst, 0x204, "%s%x", pstr, ulVal);
        strcpy_s(pstr, size, Dst);
    }
}

VOID SymbolServerGetIndexString(GUID *pGuid, unsigned int ulVal1, unsigned int ulVal2, OUT CHAR *pstr, unsigned int size)
{
    *pstr = 0;
    CatStrGUID(pstr, pGuid, size);
    CatStrDWORD(pstr, ulVal1, size);
    CatStrDWORD(pstr, ulVal2, size);
}

int wmain( int argc, wchar_t *argv[ ], wchar_t *envp[ ] )
{
    int ret = -1;

    if (argc == 2)
    {
        WCHAR wchFilePath[MAX_PATH];
        UNICODE_STRING usFilePath;
        //
        if (argv[1][1] == L':')
        {
            wcscpy_s(wchFilePath, sizeof(wchFilePath)/2, L"\\??\\");
            wcscat_s(wchFilePath, sizeof(wchFilePath)/2, argv[1]);
        }

        usFilePath.Buffer = wchFilePath;
        usFilePath.Length = wcslen(usFilePath.Buffer) * 2;
        usFilePath.MaximumLength = usFilePath.Length;

        Init_NTAPI();
        SIZE_T Size = 0;
        PVOID BaseAddress = OpenAndMapFile(&usFilePath, &Size);
        if (BaseAddress)
        {
            CHAR PdbFileName[MAX_PATH];
            GUID guid;
            DWORD age;

            PeGetPdb(BaseAddress, Size, PdbFileName, &guid, &age);
            ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);

            CHAR StrGuid[40];
            SymbolServerGetIndexString(&guid, age, 0, StrGuid, sizeof(StrGuid));

            CHAR pchPdbUrl[1024];
            strcpy_s(pchPdbUrl, sizeof(pchPdbUrl), "http://msdl.microsoft.com/download/symbols/");
            strcat_s(pchPdbUrl, sizeof(pchPdbUrl), PdbFileName);
            strcat_s(pchPdbUrl, sizeof(pchPdbUrl), "/");
            strcat_s(pchPdbUrl, sizeof(pchPdbUrl), StrGuid);
            strcat_s(pchPdbUrl, sizeof(pchPdbUrl), "/");
            strcat_s(pchPdbUrl, sizeof(pchPdbUrl), PdbFileName);
            printf("%s\n", pchPdbUrl);

            ret = 0;
        }
    }
    
    if (ret)
    {
        printf("usage : dPDB <FileName>\n");
    }
    
    getchar();
    return 0;
}