// ShellCode.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <Windows.h>

#define PEKEY 0x4d
#define DATAKEY 0x5a
enum
{
    SEC_SPACE,
    SEC_PEHEADER,
    SEC_PEDATA,
    SEC_SHELLCODE,
    SEC_NUMBERS
};

HMODULE GetMainMdouleHandle();
HMODULE GetKernel32();
DWORD HandlePE(LPBYTE pDataBuff, DWORD, DWORD);
void EraseData(char* pStr, size_t nSize);
DWORD HandleIAT(DWORD dwAddr);
FARPROC __stdcall MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
void * __cdecl mymemcpy(void * dst, const void * src, size_t count);
int __cdecl mymemcmp(const void * buf1, const void * buf2, size_t count);
DWORD MyStrlen(const char *string);

typedef  HMODULE(WINAPI* PFN_LoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef FARPROC(WINAPI* PFN_GetProcAddress)(
    _In_ HMODULE hModule,
    _In_ LPCSTR lpProcName
    );

typedef
LPVOID
(WINAPI* PFN_VirtualAlloc)(
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    );

typedef
BOOL
(WINAPI* PFN_VirtualProtect)(
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flNewProtect,
    _Out_ PDWORD lpflOldProtect
    );

typedef 
BOOL
(WINAPI* PFN_CheckRemoteDebuggerPresent)(
    __in     HANDLE hProcess,
    __inout  PBOOL pbDebuggerPresent
    );

typedef  
HANDLE
(WINAPI* PFN_GetCurrentProcess)(
    void
    );

bool MyDecrypt(unsigned char* src, size_t size, DWORD key)
{
    for (size_t i = 0; i < size; i++)
    {
        src[i] = src[i] ^ key;
    }

    return true;
}

BOOL CheckDebug()
{
    bool result = 0;
    __asm
    {
        mov eax, fs:[30h]
        mov al, BYTE PTR[eax + 2]
        mov result, al
    }
    return result;
}

BOOL CheckDebug2()
{
    int result = 0;
    __asm
    {
        mov eax, fs:[30h]
        mov eax, [eax + 68h]
        and eax, 0x70
        mov result, eax
    }
    return result;
}



void Start()
{
    if (CheckDebug())
    {
        return;
    }
    if (CheckDebug2())
    {
        return;
    }
    HMODULE hKernel32 = GetKernel32();
    char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };
    char szVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };
    //char szCheckRemoteDebuggerPresent[] = { 'C','h','e','c','k','R','e','m','o','t','e','D','e','b','u','g','g','e','r','P','r','e','s','e','n','t','\0' };
    //char szGetCurrentProcess[] = {'G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s','\0' };

    PFN_LoadLibraryA pfnLoadLibraryA = (PFN_LoadLibraryA)MyGetProcAddress(hKernel32, szLoadLibraryA);
    PFN_GetProcAddress pfnGetProcAddress = (PFN_GetProcAddress)MyGetProcAddress(hKernel32, szGetProcAddress);
    PFN_VirtualAlloc pfnVirtualAlloc = (PFN_VirtualAlloc)pfnGetProcAddress(hKernel32, szVirtualAlloc);
   // PFN_CheckRemoteDebuggerPresent pfnCheckRemoteDebuggerPresent = (PFN_CheckRemoteDebuggerPresent)pfnGetProcAddress(hKernel32, szCheckRemoteDebuggerPresent);
    //PFN_GetCurrentProcess pfnGetCurrentProcess = (PFN_GetCurrentProcess)pfnGetProcAddress(hKernel32, szGetCurrentProcess);
    /*
    * 1. ��λѹ�����ݣ���ѹ�����õ�PE�ļ�
    */
    HMODULE hModMain = GetMainMdouleHandle();
    PIMAGE_DOS_HEADER  pDosHdr = (PIMAGE_DOS_HEADER)hModMain;
    PIMAGE_NT_HEADERS  pNtHdr = (PIMAGE_NT_HEADERS)((LPBYTE)hModMain + pDosHdr->e_lfanew);
    PIMAGE_FILE_HEADER  pFileHdr = &pNtHdr->FileHeader;
    PIMAGE_OPTIONAL_HEADER  pOptHdr = &pNtHdr->OptionalHeader;
    PIMAGE_SECTION_HEADER  pSectHdr = (PIMAGE_SECTION_HEADER)((LPBYTE)pOptHdr + pFileHdr->SizeOfOptionalHeader);

    /*BOOL ret;
    if (pfnCheckRemoteDebuggerPresent(pfnGetCurrentProcess(), &ret))
    {
        return;
    }*/

    //shellcode�ڵĵ�ַ
    DWORD dwAddrOfShellCodeSec = pSectHdr[SEC_SHELLCODE].VirtualAddress + (DWORD)hModMain;
    DWORD dwAddrOfPeHeader = pSectHdr[SEC_PEHEADER].VirtualAddress + (DWORD)hModMain;
    DWORD dwAddrOfPeData = pSectHdr[SEC_PEDATA].VirtualAddress + (DWORD)hModMain;

    DWORD DataSize = pSectHdr[SEC_PEHEADER].SizeOfRawData + pSectHdr[SEC_PEDATA].SizeOfRawData;
    LPBYTE pDecomData = (LPBYTE)pfnVirtualAlloc(NULL, DataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    mymemcpy(pDecomData, (LPBYTE)dwAddrOfPeHeader, pSectHdr[SEC_PEHEADER].SizeOfRawData);
    mymemcpy(pDecomData + pSectHdr[SEC_PEHEADER].SizeOfRawData, (LPBYTE)dwAddrOfPeData, pSectHdr[SEC_PEDATA].SizeOfRawData);

    MyDecrypt(pDecomData, pSectHdr[SEC_PEHEADER].SizeOfRawData, PEKEY);
    DWORD SrcSize = pSectHdr[SEC_PEDATA].SizeOfRawData;
    DWORD SrcOffset = pSectHdr[SEC_PEHEADER].SizeOfRawData;
    //MyDecrypt(pDecomData + pSectHdr[SEC_PEHEADER].SizeOfRawData,pSectHdr[SEC_PEDATA].SizeOfRawData, DATAKEY);
    DWORD dwOldProtect = 0;
    /*
    *  ����PE�����������ݣ�������ֱ�
    */

    DWORD dwOep = HandlePE(pDecomData, SrcOffset, SrcSize);

    __asm jmp dwOep;
}

void EraseData(char* pStr, size_t nSize)
{
    for (int i = 0; i < nSize; i++)
    {
        pStr[i] = '\0';
    }
}

DWORD HandleIAT(DWORD dwAddr)
{
    char szCode[12] = { 0x51, 0x53, 0x5b, 0x59, 0x68, 0x00, 0x00, 0x00, 0x00, 0xc3, 0xc3 };
    mymemcpy(szCode + 5, &dwAddr, sizeof(DWORD));

    HMODULE hKernel32 = GetKernel32();
    char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };
    char szVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };

    PFN_GetProcAddress pfnGetProcAddress = (PFN_GetProcAddress)MyGetProcAddress(hKernel32, szGetProcAddress);
    PFN_VirtualAlloc pfnVirtualAlloc = (PFN_VirtualAlloc)pfnGetProcAddress(hKernel32, szVirtualAlloc);
    LPVOID pDst = pfnVirtualAlloc(NULL, 12, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pDst == nullptr)
    {
        return 0;
    }
    mymemcpy(pDst, szCode, 12);

    return (DWORD)pDst;
}

int MyStrcmp(const char *string1, const char *string2)
{
    DWORD dwStrlen1 = MyStrlen(string1);
    DWORD dwStrlen2 = MyStrlen(string2);
    char cRes = 0;

    DWORD dwCount = 0;
    while (TRUE)
    {
        cRes = string1[dwCount] - string2[dwCount];
        if (cRes != 0)
        {
            return cRes;
        }

        dwCount++;
        if (dwCount >= dwStrlen1 || dwCount >= dwStrlen2)
        {
            break;
        }
    }

    return 0;
}

DWORD MyStrlen(const char *string)
{
    DWORD dwLen = 0;
    __asm
    {
        mov ecx, -1
        mov edi, string
        xor eax, eax
        repnz scasb
        not ecx
        dec ecx

        mov dwLen, ecx
    }

    return dwLen;
}


DWORD HandlePE(LPBYTE pDecomDataBuff, DWORD SrcOffset, DWORD SrcSize)
{
    HMODULE hKernel32 = GetKernel32();
    char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };
    char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };

    PFN_LoadLibraryA pfnLoadLibraryA = (PFN_LoadLibraryA)MyGetProcAddress(hKernel32, szLoadLibraryA);
    PFN_GetProcAddress pfnGetProcAddress = (PFN_GetProcAddress)MyGetProcAddress(hKernel32, szGetProcAddress);
    PFN_VirtualProtect pfnVirtualProtect = (PFN_VirtualProtect)pfnGetProcAddress(hKernel32, szVirtualProtect);

    // 2. ����PE�ļ������ݵ��ս�
    IMAGE_IMPORT_DESCRIPTOR EndImpTable = { 0 };
    HMODULE hModule = GetMainMdouleHandle();


    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pDecomDataBuff;
    DWORD pdwImport = (DWORD)pDosHeader->e_minalloc;
    DWORD pdwIAT = (DWORD)pDosHeader->e_ip;


    PIMAGE_NT_HEADERS pNtHeader = PIMAGE_NT_HEADERS((DWORD)pDosHeader->e_lfanew + (DWORD)pDecomDataBuff);

    DWORD dwFileHeaderAddr = (DWORD)(&pNtHeader->FileHeader);
    DWORD dwOptionalHeaderAddr = (DWORD)(&pNtHeader->OptionalHeader);

    PIMAGE_FILE_HEADER pFileHdr = (PIMAGE_FILE_HEADER)(dwFileHeaderAddr);
    DWORD dwSizeOfOptHdr = (DWORD)pFileHdr->SizeOfOptionalHeader;
    DWORD dwNumOfSecs = (DWORD)pFileHdr->NumberOfSections;

    PIMAGE_OPTIONAL_HEADER pOptionalHdr = (PIMAGE_OPTIONAL_HEADER)dwOptionalHeaderAddr;
    PIMAGE_SECTION_HEADER pSecHdrs = (PIMAGE_SECTION_HEADER)(dwOptionalHeaderAddr + dwSizeOfOptHdr);
    DWORD dwSizeOfHdrs = pOptionalHdr->SizeOfHeaders;

    //PIMAGE_DATA_DIRECTORY pImgDataDir = (PIMAGE_DATA_DIRECTORY)((DWORD)pOptionalHdr->DataDirectory + sizeof(IMAGE_DATA_DIRECTORY));
    PIMAGE_IMPORT_DESCRIPTOR pImpTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pdwImport + (DWORD)hModule);
    //__asm int 3

    DWORD dwOEP = (DWORD)pOptionalHdr->AddressOfEntryPoint + (DWORD)hModule;

    // �޸��ڴ�����
    DWORD dwOldProtect = 0;
    bool bRet = pfnVirtualProtect(hModule, pOptionalHdr->SizeOfHeaders, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    if (bRet == false)
    {
        return 0;
    }
    //VirtualProtectEx
    // ����PEͷ
    mymemcpy(hModule, pDecomDataBuff, dwSizeOfHdrs);
    MyDecrypt(pDecomDataBuff + SrcOffset, SrcSize, DATAKEY);
    // ���ݽڱ�������Ŀ¼����Ӧ���ڴ�λ��
    LPVOID pSrcAddr = nullptr;
    DWORD dwSizeToCpy = 0;
    LPVOID pDstAddr = nullptr;
    for (int i = 0; i < dwNumOfSecs; i++)
    {
        pSrcAddr = (LPVOID)((DWORD)pSecHdrs->PointerToRawData + (DWORD)pDecomDataBuff);		//��ȡԭ���ݵĵ�ַ
        dwSizeToCpy = pSecHdrs->SizeOfRawData;										//��ȡ�������ݵĴ�С
        pDstAddr = (LPVOID)((DWORD)pSecHdrs->VirtualAddress + (DWORD)hModule);		//��ȡ���ݿ�����Ŀ���ַ
        mymemcpy(pDstAddr, pSrcAddr, dwSizeToCpy);
        pSecHdrs = (PIMAGE_SECTION_HEADER)((DWORD)pSecHdrs + sizeof(IMAGE_SECTION_HEADER));
    }

    /*
    *  �������
    */
    CHAR* pDllName = nullptr;
    DWORD dwINT = 0;
    DWORD dwIAT = 0;

    while (true)
    {
        //�ж��Ƿ�Ϊ����������
        int nRet = mymemcmp(&EndImpTable, pImpTable, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (nRet == 0)
        {
            break;
        }

        // ����2: ���name�ֶ��Ƿ�Ϊ��, Ϊ����ֹͣ���ص����
        if (!pImpTable->Name)
        {
            break;
        }
        pDllName = (CHAR*)((DWORD)pImpTable->Name + (DWORD)hModule);

        // ����3: ���IAT�ֶ��Ƿ�Ϊ��, Ϊ���������˵������
        if (pImpTable->FirstThunk == NULL)
        {
            pImpTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImpTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
            continue;
        }

        // ����4: ���INT�ֶ��Ƿ�Ϊ��, Ϊ����ȡIAT�ֶ���Ϣ
        if (pImpTable->OriginalFirstThunk)
        {
            pImpTable->OriginalFirstThunk;
        }

        dwIAT = ((DWORD)pImpTable->FirstThunk + (DWORD)hModule);
        dwINT = dwIAT;
        // ����5: ����loadLibrary��ȡ���ÿ�ľ��, ʧ����������ʧ��
        HMODULE hLib = pfnLoadLibraryA(pDllName);
        if (hLib == NULL)
        {
            return 0;
        }

        /*

        �ڲ�ѭ��

        */

        //����6: ȡIAT�ĵ�һ��, �ж��Ƿ�Ϊ��, Ϊ���������˵������, FreeLibrary
        if (*(DWORD*)dwIAT == 0)
        {
            pImpTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImpTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
            continue;
        }

        //����7: ȡINT��ÿһ��, ʹ��GetProcAddress��ȡ���뺯���ĵ�ַ, ��дIAT, ʧ�����˳�����
        while (*(DWORD*)dwINT != 0)
        {
            if ((DWORD)dwINT & 0x80000000)	// ��ŵ���
            {
                WORD wOrder = *(DWORD*)dwINT & 0xffff;
                *(DWORD*)dwIAT = (DWORD)pfnGetProcAddress(hLib, (LPCSTR)wOrder);
                if (*(DWORD*)dwIAT == 0)
                {
                    return 0;
                }
            }
            else							// ���Ƶ���
            {
                /*PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(*(DWORD*)dwINT + (DWORD)hModule);
                *(DWORD*)dwIAT = (DWORD)pfnGetProcAddress(hLib, pName->Name);
                if (*(DWORD*)dwIAT == 0)
                {
                    return 0;
                }
                *(WORD *)pName = 0;
                EraseData((char *)pName + 2, MyStrlen((char *)pName + 2));*/
                PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(*(DWORD*)dwINT + (DWORD)hModule);
                //*(DWORD*)dwIATAddr = (DWORD)pfnGetProcAddress(hLib, pName->Name);
                char szTarget[] = { 0x5F, 0x77, 0x63, 0x6D, 0x64, 0x6C, 0x6E, 0x0 };		//_wcmdln����CALL.��Ҫ���⴦��
                if (MyStrcmp(pName->Name, szTarget) != 0)
                {
                    DWORD dwFuncAddr = (DWORD)pfnGetProcAddress(hLib, pName->Name);
                    *(DWORD*)dwIAT = HandleIAT(dwFuncAddr);							//��ַ����
                    if (*(DWORD*)dwIAT == 0)
                    {
                        *(DWORD*)dwIAT = (DWORD)pfnGetProcAddress(hLib, pName->Name);
                    }
                }
                else
                {
                    *(DWORD*)dwIAT = (DWORD)pfnGetProcAddress(hLib, pName->Name);
                }

                *(WORD *)pName = 0;
                EraseData((char *)pName + 2, MyStrlen((char *)pName + 2));

            }

            dwIAT = ((DWORD)dwIAT + sizeof(DWORD));
            dwINT = ((DWORD)dwINT + sizeof(DWORD));
        }
        //EraseData((CHAR*)((DWORD)pImpTable->Name), MyStrlen((CHAR*)(DWORD)pImpTable->Name));
        EraseData((CHAR*)((DWORD)pImpTable->Name + (DWORD)hModule), MyStrlen((CHAR*)((DWORD)pImpTable->Name + (DWORD)hModule)));
        pImpTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pImpTable + sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    // 4. �����ض�λ��



    return dwOEP;
}

HMODULE GetMainMdouleHandle()
{
    HMODULE hMainMdoule = NULL;
    __asm {
        mov eax, fs:[0x18];// �õ�TEB
        mov eax, [eax + 0x30]; //�õ�PEB
        mov eax, [eax + 0x0c]; //Ldr
        mov eax, [eax + 0x0c]; //��ģ��
        mov eax, [eax + 0x18]; //kernel32 ��ַ
        mov hMainMdoule, eax
    }
    return hMainMdoule;
}

HMODULE GetKernel32()
{
    HMODULE hKernel32 = NULL;
    __asm {
        mov eax, fs:[0x18];// �õ�TEB
        mov eax, [eax + 0x30]; //�õ�PEB
        mov eax, [eax + 0x0c]; //Ldr
        mov eax, [eax + 0x0c]; //��ģ��
        mov eax, [eax]; //ntll
        mov eax, [eax]; //kernel32
        mov eax, [eax + 0x18]; //kernel32 ��ַ
        mov hKernel32, eax
    }
    return hKernel32;
}

int __cdecl mymemcmp(
    const void * buf1,
    const void * buf2,
    size_t count
)
{
    if (!count)
        return(0);

    while (--count && *(char *)buf1 == *(char *)buf2) {
        buf1 = (char *)buf1 + 1;
        buf2 = (char *)buf2 + 1;
    }

    return(*((unsigned char *)buf1) - *((unsigned char *)buf2));
}

void * __cdecl mymemcpy(
    void * dst,
    const void * src,
    size_t count
)
{
    void * ret = dst;
    /*
    * copy from lower addresses to higher addresses
    */
    while (count--) {
        *(char *)dst = *(char *)src;
        dst = (char *)dst + 1;
        src = (char *)src + 1;
    }


    return(ret);
}

FARPROC __stdcall MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    //�õ������ַ
    IMAGE_DOS_HEADER *lpDosHeader = (IMAGE_DOS_HEADER *)hModule;
    IMAGE_NT_HEADERS *lpNTHeaders = (IMAGE_NT_HEADERS *)((BYTE *)lpDosHeader + lpDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER *lpOptionalHeader = &(lpNTHeaders->OptionalHeader);
    IMAGE_DATA_DIRECTORY *lpDataDirectoryExport = &(lpOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY *lpExportTab = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)lpDosHeader + lpDataDirectoryExport->VirtualAddress);

    //���������Ϣ
    DWORD dwBase = lpExportTab->Base;
    DWORD dwNumOfFunctions = lpExportTab->NumberOfFunctions;
    DWORD dwNumOfNames = lpExportTab->NumberOfNames;
    DWORD *AryExportFuncs = (DWORD *)((BYTE *)lpDosHeader + lpExportTab->AddressOfFunctions);
    DWORD *AryFuncNames = (DWORD *)((BYTE *)lpDosHeader + lpExportTab->AddressOfNames);
    WORD *AryNameOrdinals = (WORD *)((BYTE *)lpDosHeader + lpExportTab->AddressOfNameOrdinals);
    WORD wOrdinal = -1;


    CHAR ArrayName[20] = { 0 };
    mymemcpy(ArrayName, lpProcName, strlen(lpProcName));

    //��鴫������Ǻ������������
    //��������ַ�����
    if (*(DWORD *)ArrayName > 0xffff)
    {
        //�������������Ƚ��ַ���
        DWORD dwCountFunc = 0;
        while (dwCountFunc < dwNumOfNames)
        {
            int iRet = MyStrcmp(lpProcName, (LPCSTR)(AryFuncNames[dwCountFunc] + (BYTE *)lpDosHeader));
            if (0 == iRet)
            {
                break;
            }

            dwCountFunc++;
        }

        //û�ҵ�
        if (dwCountFunc >= dwNumOfNames)
        {
            return NULL;
        }
        //�ҵ���
        else
        {
            //��AddressOfOrinalNames�����ж�Ӧ��ġ���š�
            wOrdinal = AryNameOrdinals[dwCountFunc];

        }
    }
    //������ŵ����
    else
    {
        wOrdinal = LOWORD(lpProcName);
        wOrdinal = wOrdinal - LOWORD(dwBase);
    }

    //�Դ�Ϊ�±꣬����AddressOfFunctions
    FARPROC lpExportFunc = (FARPROC)(AryExportFuncs[wOrdinal] + (BYTE *)lpDosHeader);

    return lpExportFunc;
}
