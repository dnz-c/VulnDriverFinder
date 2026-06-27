# wnBios64.sys — Reverse Engineering Analysis

**File:** `1432790590_wnBios64.sys`
**SHA-256:** `530d9223ec7e4123532a403abef96dfd1af5291eb49497392ff5d14d18fccfbb`
**MD5:** `a55bcd596643362ddb2ee558aa238baf`
**Architecture:** x86-64, Windows kernel driver (.sys)
**Image base:** `0x10000`, Image size: `0x7000`
**Verdict:** **CRITICALLY VULNERABLE — arbitrary physical memory R/W + arbitrary I/O port R/W exposed to any usermode process**

---

## 1. Overview

`wnBios64.sys` (WinBIOS64) is a kernel-mode driver that exposes a named device `\Device\WNBIOS` with the usermode-accessible symlink `\\.\WNBIOS`. It provides hardware-level access primitives — physical memory mapping, raw I/O port reads/writes — with **zero caller privilege checks** beyond requiring the device to be open.

Any process with `GENERIC_READ | GENERIC_WRITE` access to `\\.\WNBIOS` can:
- Map **any** physical address range into its own address space for direct R/W
- Read and write **any** hardware I/O port (8/16/32-bit)
- Discover the physical address and VA of a pre-allocated 64 KB kernel buffer

This is a classic "bring your own vulnerable driver" (BYOVD) primitive.

---

## 2. Segment Layout

| Segment | Start    | End      | Perms | Purpose                             |
|---------|----------|----------|-------|-------------------------------------|
| .text   | `0x11000`| `0x12000`| r-x   | Code (DriverEntry, handlers)        |
| .idata  | `0x12000`| `0x120A8`| r--   | Import directory                    |
| .rdata  | `0x120A8`| `0x13000`| r--   | Read-only data, strings             |
| .data   | `0x13000`| `0x14000`| rw-   | Globals (buffer pointer, phys addr) |
| .pdata  | `0x14000`| `0x15000`| r--   | Exception unwind tables             |
| INIT    | `0x15000`| `0x16000`| rwx   | DriverEntry (discardable)           |

---

## 3. Function Summary

| Address   | Name (IDB)           | Size  | Role                                                  |
|-----------|----------------------|-------|-------------------------------------------------------|
| `0x11008` | `DriverEntry`        | 0xF5  | Driver initialization, device/symlink creation        |
| `0x11104` | `IrpDispatcher`      | 0x517 | Unified IRP handler (CREATE/CLOSE/DEVICE_CONTROL)     |
| `0x11624` | `DriverUnload`       | 0x54  | Cleanup: free buffer, delete symlink & device         |
| `0x11680` | `MapPhysicalMemory`  | 0x23F | Core: maps physical address via `\Device\PhysicalMemory` |
| `0x118D0` | `OutByteWrapper`     | 0x0F  | Executes `OUT dx, al` — byte write to I/O port        |

### Globals (`.data` segment)

| Address   | Name            | Type    | Description                                       |
|-----------|-----------------|---------|---------------------------------------------------|
| `0x13128` | `BaseAddress`   | `PVOID` | VA of 64KB physically contiguous kernel buffer    |
| `0x13130` | `qword_13130`   | `QWORD` | Physical address of that buffer                   |
| `0x13120` | `dword_13120`   | `DWORD` | Scratch: packed port/value for PORT_WRITE_ALT     |
| `0x13124` | `word_13124`    | `WORD`  | Scratch: upper word field                         |
| `0x13126` | `byte_13126`    | `BYTE`  | Scratch: byte field                               |

---

## 4. DriverEntry (`0x11008`)

```c
NTSTATUS DriverEntry(_DRIVER_OBJECT *DriverObject, PUNICODE_STRING RegistryPath)
```

**Actions:**
1. Allocates 64 KB (`0x10000`) of physically contiguous memory below 4 GB:
   `MmAllocateContiguousMemory(0x10000, {.QuadPart = 0xFFFFFFFF})`
   → VA stored in global `BaseAddress`, PA stored in `qword_13130`
2. Creates `\Device\WNBIOS` (DeviceType = `0x8010`, **no security descriptor** → world-readable)
3. Registers `IrpDispatcher` for `IRP_MJ_CREATE[0]`, `IRP_MJ_CLOSE[2]`, `IRP_MJ_DEVICE_CONTROL[0xE]`
4. Creates symlink `\DosDevices\WNBIOS` → accessible as `\\.\WNBIOS` from usermode

---

## 5. IrpDispatcher (`0x11104`) — IOCTL Dispatch Table

Only `IRP_MJ_DEVICE_CONTROL` IOCTLs are processed. All other major functions complete with `STATUS_SUCCESS`. All IOCTLs use **METHOD_BUFFERED** (low 2 bits of IoControlCode = 0). There are **no privilege checks** — any caller can open the device and issue any IOCTL.

`InputBufferLength` (at `IO_STACK_LOCATION+0x10`) drives a `memmove` from `SystemBuffer` (= `IRP->AssociatedIrp.SystemBuffer`) onto the local stack at `&map_size`. The IoControlCode is at `IO_STACK_LOCATION+0x18`.

### IOCTL Table

| IOCTL Code   | Name                   | Input Size | Description                                     |
|--------------|------------------------|------------|-------------------------------------------------|
| `0x80102040` | `MAP_PHYSICAL_MEMORY`  | 40 bytes   | Map any physical address into caller's VA space |
| `0x80102044` | `UNMAP_PHYSICAL_MEMORY`| 40 bytes   | Unmap previously mapped physical memory         |
| `0x80102050` | `READ_IO_PORT`         | 7 bytes    | Read 1/2/4 bytes from a hardware I/O port       |
| `0x80102054` | `WRITE_IO_PORT`        | 7 bytes    | Write 1/2/4 bytes to a hardware I/O port        |
| `0x80102058` | `ALLOC_PHYS_NONCACHED` | ≥0x30 bytes| Alloc non-cached memory, return physical addr   |
| `0x8010205C` | `PORT_WRITE_BYTE_ALT`  | 7 bytes    | Alternate port byte-write (packed format)       |
| `0x80102060` | `GET_PHYS_INFO`        | 40 bytes   | Return VA and phys addr of pre-allocated buffer |

CTL_CODE decomposition: `CTL_CODE(DeviceType=0x8010, Function, METHOD_BUFFERED, FILE_ANY_ACCESS)`

---

## 6. IOCTL Detail: MAP_PHYSICAL_MEMORY (`0x80102040`)

**This is the primary vulnerability.**

### Input/Output Structure

The single system buffer (METHOD_BUFFERED) overlaps with the driver's local stack layout starting at `&map_size`:

```c
// Shared input/output buffer (40 bytes = 0x28)
struct WNBIOS_PHYS_MEM {
    UINT64  Size;          // [in]  bytes to map
    UINT64  PhysAddr;      // [in]  target physical address (any value accepted)
    HANDLE  SectionHandle; // [out] section handle (pass back to UNMAP)
    PVOID   MappedVA;      // [out] usermode virtual address of mapped region
    PVOID   SectionObject; // [out] section object pointer (pass back to UNMAP)
};
```

### Stack Layout → IOCTL Buffer Mapping

Confirmed from disassembly at `0x115a2–0x115c8`:

```
Stack offset  Buffer offset  Field
─────────────────────────────────────────────────────────────
[rsp+0x60]    [0x00..0x07]   map_size       (CommitSize → rdx → arg2)
[rsp+0x68]    [0x08..0x0F]   phys_addr      (BusAddress → rcx → arg1)
[rsp+0x70]    [0x10..0x17]   section_handle (→ &Handle = r9 = *OutSectionHandle)
[rsp+0x78]    [0x18..0x1F]   mapped_va      (→ &mapped_va = r8 = *OutMappedVA)
[rsp+0x80]    [0x20..0x27]   section_obj    (→ &Object on stack = *OutSectionObj)
```

Disasm evidence (call site `0x115a7–0x115c8`):
```asm
115a7:  mov rdx, [rsp+map_size]       ; CommitSize = input[0x00..0x07]
115ac:  mov rcx, [rsp+phys_addr]      ; PhysAddr   = input[0x08..0x0F]
115b1:  lea r11, [rsp+section_obj]    ; &section_obj output
115b9:  lea r9,  [rsp+section_handle] ; &section_handle output → output[0x10]
115be:  lea r8,  [rsp+mapped_va]      ; &mapped_va output     → output[0x18]
115c3:  mov [rsp+0x20], r11           ; 5th arg: &section_obj → output[0x20]
115c8:  call MapPhysicalMemory
```

### Execution Flow

```
IrpDispatcher:
  memmove(&map_size, SystemBuffer, InputBufferLength)   ; copy user input to stack
  MapPhysicalMemory(phys_addr, map_size,                ; call with user-supplied phys addr
                   &mapped_va, &section_handle,
                   &section_obj)
  memmove(SystemBuffer, &map_size, InputBufferLength)   ; copy output back to user
```

### MapPhysicalMemory (`0x11680`)

```c
NTSTATUS MapPhysicalMemory(
    PHYSICAL_ADDRESS PhysAddr,     // rcx: physical address to map
    ULONG_PTR        MapSize,      // rdx: number of bytes to map
    PVOID           *OutMappedVA,  // r8:  receives the usermode VA
    HANDLE          *OutSectionHandle, // r9
    PVOID           *OutSectionObj     // [rsp+0x28]
)
```

1. `RtlInitUnicodeString(L"\\Device\\PhysicalMemory")`
2. `ZwOpenSection(OutSectionHandle, SECTION_ALL_ACCESS=0xF001F, &ObjAttribs)`
3. `ObReferenceObjectByHandle(*OutSectionHandle, SECTION_ALL_ACCESS, NULL, 0, OutSectionObj, NULL)`
4. `HalTranslateBusAddress(Isa, 0, PhysAddr,          &AddrSpace, &TranslatedStart)`
5. `HalTranslateBusAddress(Isa, 0, PhysAddr + MapSize, &AddrSpace, &TranslatedEnd)`
6. `CommitSize = TranslatedEnd - TranslatedStart`
7. `ZwMapViewOfSection(*OutSectionHandle, (HANDLE)-1 /*NtCurrentProcess*/, &BaseAddr, 0,`
   `  CommitSize, &SectionOffset=TranslatedStart, &CommitSize, ViewShare, 0, PAGE_READWRITE|PAGE_NOCACHE=0x204)`
   → on `STATUS_CONFLICTING_ADDRESSES (-0x3FFFEBC8)`: retry with `PAGE_READWRITE=0x4`
8. `*OutMappedVA = BaseAddr + (TranslatedStart - SectionOffset)`  (page-alignment adjust)

After step 8, the usermode caller holds a virtual address that directly aliases the requested physical address — full read/write access with no further checks.

---

## 7. IOCTL Detail: UNMAP_PHYSICAL_MEMORY (`0x80102044`)

Pass back the same 40-byte struct returned by MAP. The driver:
- `ZwUnmapViewOfSection((HANDLE)-1, input[0x18..0x1F])` — removes the mapping (mapped_va)
- `ObfDereferenceObject(input[0x20..0x27])` — releases kernel object ref (section_obj, if nonzero)
- `ZwClose(input[0x10..0x17])` — closes the section handle (section_handle)

Disasm evidence (`0x11559–0x11588`):
```asm
11559:  mov rdx, [rsp+mapped_va]      ; BaseAddress for ZwUnmapViewOfSection
1155e:  mov rbx, [rsp+section_obj]    ; Object for ObfDereferenceObject
11566:  mov rsi, [rsp+section_handle] ; Handle for ZwClose
1156b:  or  rcx, -1                   ; NtCurrentProcess = (HANDLE)-1
1156f:  call ZwUnmapViewOfSection
1157f:  call ObfDereferenceObject
11588:  call ZwClose
```

---

## 8. IOCTL Detail: READ_IO_PORT (`0x80102050`)

```c
// Input buffer (7 bytes)
struct {
    UINT16 Port;         // [0..1] I/O port number (0x0000–0xFFFF)
    UINT8  _unused[4];   // [2..5] ignored for read
    UINT8  AccessSize;   // [6]    1=byte, 2=word, 4=dword
};
// Output: system buffer [0..3] = read value (UINT32)
// IoStatus.Information = 4 always
```

Executes `IN al/ax/eax, dx` based on `AccessSize`. Result written back to output buffer `[0..3]`.

AccessSize encoding (from disasm branch at `0x114e8`):
- `1` → `IN al, dx` (`__inbyte`)
- `2` → `IN ax, dx` (`__inword`)
- `4` → `IN eax, dx` (`__indword`)
- other → returns `input[2..5]` unchanged (no hardware access)

---

## 9. IOCTL Detail: WRITE_IO_PORT (`0x80102054`)

```c
// Input buffer (7 bytes)
struct {
    UINT16 Port;       // [0..1] I/O port number
    UINT32 Value;      // [2..5] value to write (1/2/4 bytes used per AccessSize)
    UINT8  AccessSize; // [6]    1=byte, 2=word, 4=dword
};
```

Executes `OUT dx, al/ax/eax` based on `AccessSize`. Invalid size → no hardware access.

---

## 10. IOCTL Detail: GET_PHYS_INFO (`0x80102060`)

Returns information about the 64 KB pre-allocated contiguous buffer. No meaningful input required; provide a 40-byte output buffer.

| Output Offset | Size | Field | Value |
|---------------|------|-------|-------|
| 0x00 | 8 | Size       | `0x10000` (hardcoded) |
| 0x08 | 8 | PhysAddr   | PA of `BaseAddress` global (from `qword_13130`) |
| 0x10 | 8 | —          | **Uninitialized stack garbage — do not use** |
| 0x18 | 8 | MappedVA   | Kernel VA of `BaseAddress` global |
| 0x20 | 8 | —          | **Uninitialized stack garbage — do not use** |

Note: `output[0x10]` and `output[0x20]` are uninitialized locals from the fresh stack frame. Only `output[0x00]` (size), `output[0x08]` (phys addr), and `output[0x18]` (kernel VA) are reliable.

---

## 11. IOCTL Detail: ALLOC_PHYS_NONCACHED (`0x80102058`)

Allocates 0x30 bytes of non-cached kernel memory, copies a 0x30-byte descriptor from the caller into it, retrieves the physical address via `MmGetPhysicalAddress`, then copies everything back. Used for preparing BIOS/SMI call descriptor tables at a known physical address. The physical address is returned in the caller's buffer.

---

## 12. IOCTL Detail: PORT_WRITE_BYTE_ALT (`0x8010205C`)

Single-byte I/O port write using the global scratch area + `OutByteWrapper`.

```c
// Input (7 bytes minimum, reads from SystemBuffer directly via p_Type)
// input[0..1] = port number (UINT16, stored in global dword_13120[0..1])
// input[2]    = value to write (BYTE, stored in global dword_13120[2])
// input[4..6] = additional bytes stored in word_13124, byte_13126
```

Calls `OutByteWrapper(_, input[2], (UINT16)dword_13120)` = `__outbyte(port, value)`. Also performs `MmGetPhysicalAddress` on a staging buffer — side effect of reading global state into a VA.

---

## 13. Security Analysis

### Vulnerability Classification

| # | Vulnerability | Impact |
|---|---------------|--------|
| 1 | Arbitrary physical memory read | Read any physical page: kernel memory, credentials, SMEP bits |
| 2 | Arbitrary physical memory write | Write to any physical address: patch kernel, DKOM, PTE manipulation |
| 3 | Arbitrary I/O port read | Read CMOS, PCI config, keyboard, any hardware register |
| 4 | Arbitrary I/O port write | Write CMOS, SMI trigger (port 0xB2), power management registers |
| 5 | No device security descriptor | Any low-integrity process (even Medium IL) can open device |

### Root Cause

- `IoCreateDevice` called with `NULL` security descriptor → OS applies default permissive DACL
- `IrpDispatcher` performs **zero** privilege validation (`ZwGetCurrentProcessToken`, `SePrivilegeCheck`, ACL checks) before executing any IOCTL
- `MapPhysicalMemory` accepts **any** `PhysAddr` with **no bounds checking** whatsoever
- Physical memory mapping targets `(HANDLE)-1` = current (usermode) process

### Exploitation

From usermode with `GENERIC_READ | GENERIC_WRITE` on `\\.\WNBIOS`:

```
// Read/write any physical address:
MAP_PHYSICAL_MEMORY(phys=X, size=0x1000) → usermode VA P
*(QWORD *)(P + offset) = desired_value
UNMAP_PHYSICAL_MEMORY(P)

// Practical attacks:
// - Token replacement: find SYSTEM EPROCESS via phys scan, patch target process token
// - Disable DSE: find ci!g_CiOptions in physical memory and zero it
// - KASLR defeat: scan physical memory for MZ/PE headers to locate ntoskrnl base
// - Bypass PatchGuard: write via physical bypasses virtual-address PG monitoring
// - I/O attack: PortWrite(0x70/0x71) to corrupt CMOS/RTC
// - SMI trigger: PortWrite(0xB2, ...) to invoke System Management Interrupt
```

Physical R/W bypasses all virtual-address-based protections (SMEP, SMAP, VTL, shadow stacks) because writes go through `\Device\PhysicalMemory` to the underlying frames directly.

---

## 14. IDB Annotations

All applied and saved to `1432790590_wnBios64.sys.i64`:

| Type | Detail |
|------|--------|
| Function renames | `IrpDispatcher`, `DriverUnload`, `MapPhysicalMemory`, `OutByteWrapper` |
| Function types | NTSTATUS/void prototypes with named parameters for all 4 functions |
| Local var renames | `map_size`, `phys_addr`, `section_handle`, `mapped_va`, `section_obj` in IrpDispatcher |
| Comments | 31 inline comments at: DriverEntry init, all 7 IOCTL handler entry points, memmove copy ops, MapPhysicalMemory internal calls (ZwOpenSection, ObReferenceObjectByHandle, HalTranslateBusAddress×2, ZwMapViewOfSection, retry, VA adjustment), OutByteWrapper |

---

## 15. Methodology

1. Opened binary in IDA Pro via idalib MCP server (session `c855257f`) with Hex-Rays decompiler
2. `survey_binary` → 10 functions, 7 IOCTLs identified, HAL + ntoskrnl imports catalogued
3. `decompile` all 5 non-library functions → identified dispatch logic, MapPhysicalMemory core, buffer copy patterns
4. `disasm` of IrpDispatcher (271 instructions) → confirmed exact argument passing to MapPhysicalMemory at `0x115a7–0x115c8`; confirmed IOCTL branch targets; confirmed AccessSize encoding for port I/O
5. `stack_frame` of IrpDispatcher and MapPhysicalMemory → confirmed 40-byte buffer layout with field-by-field offset verification
6. Cross-referenced Windows kernel structures (IRP, IO_STACK_LOCATION, IO_STATUS_BLOCK) to correctly identify IoControlCode/InputBufferLength offsets
7. Verified METHOD_BUFFERED pattern: IOCTL low 2 bits = 0; SystemBuffer = both input and output
8. Decoded CTL_CODE values: DeviceType=0x8010, Function=0x810–0x818, Method=0, Access=0
9. Traced `MapPhysicalMemory` → `HalTranslateBusAddress` → `ZwMapViewOfSection(-1)` chain confirming current-process mapping
10. Applied renames, type signatures, local variable renames, and 31 comments; saved IDB
