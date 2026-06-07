.code

; syscallNumber is populated at runtime by kernelHelper::resolveKernelArtifacts
; (read from the ntdll!NtSetQuotaInformationFile prologue), so this stub stays
; correct across Windows builds without recompilation.
EXTERN syscallNumber: DWORD

; Standard x64 syscall ABI — works for any kernel routine arity. Args 1..4
; ride RCX/RDX/R8/R9 (RCX is moved to R10 because `syscall` clobbers RCX with
; the return address), and args 5+ ride the caller's stack at [rsp+0x28]+.
; The kernel-side dispatcher reads the stack-arg count from the low 4 bits of
; the KiServiceTable entry and copies them onto the kernel stack on entry.
HijackedSyscall PROC
	mov r10, rcx
	mov eax, syscallNumber
	syscall
	ret
HijackedSyscall ENDP

end
