# 1764903899_LnvMSRIO.sys — Reverse Engineering Analysis

## Identification

| Field | Value |
|---|---|
| Filename | `1764903899_LnvMSRIO.sys` |
| MD5 | `ee07ab695f314bd9203d49e9d69ad92f` |
| SHA-256 | `8518a109a37b651b8ecad6e06472d2371f8d3049c3b952543195159dd02ed3be` |
| Architecture | x86-64 |
| Image base | `0x140000000` |
| Image size | `0xC000` |
| Vendor | Lenovo |
| Purpose | Intel IMC MMIO + CPU thermal/power MSR access for power management |

## Device Exposure

| Object | Value |
|---|---|
| Device name | `\Device\WinMsrDev` |
| Symbolic link | `\DosDevices\WinMsrDev` |
| Device SDDL | `D:P(A;;GA;;;SY)` — **NT AUTHORITY\SYSTEM only** |
| FltMgr port | `\LnvMiniFilterDriverPort` — SYSTEM-only ACL, max 1 client |

The device is **not accessible to unprivileged or even administrator users** — the DACL explicitly grants only `GENERIC_ALL` to SYSTEM. Any exploitation requires prior access as SYSTEM or via a vulnerable Lenovo service running as SYSTEM.

## Driver Architecture

The driver registers in two ways:

1. **Standard IRP dispatch** — `IrpDispatch_CreateCloseDeviceControl` (`0x140001650`) handles `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, and `IRP_MJ_DEVICE_CONTROL` for `\Device\WinMsrDev`. This is where all sensitive operations live.

2. **FltMgr communication port** — `\LnvMiniFilterDriverPort` exposes `FltMgr_MessageNotifyCallback` (`0x140001B00`) which only accepts command codes 0 and 1 (both no-ops). No sensitive operations are accessible via this channel.

Additionally, `PsSetCreateProcessNotifyRoutineEx` registers `ProcessCreateNotifyRoutine` to monitor process creation (typical for Lenovo security/management software).

## IOCTL Interface

All IOCTLs use `METHOD_BUFFERED`. Device type = `0x9C40`, access = `FILE_ANY_ACCESS`.

### IOCTL 0x9C402000 — Get Version
- **Input**: none required  
- **Output**: DWORD `0x01000000`  
- Returns a hardcoded version/magic constant.

### IOCTL 0x9C402004 — Get Handle Count
- **Input**: none required  
- **Output**: DWORD `g_OpenHandleCount`  
- Returns the current number of open handles to the device.

### IOCTL 0x9C4021D4 — Initialize CPU Model (`Ioctl_InitCpuModel`)
- **Input**: `{ DWORD cpu_family; CHAR[4] platform_id; ... }`  
- **Output**: none  
- **Must be called first** before MSR or MMIO operations will work.  
- If `cpu_family` is 51, 53, or 54, populates the MSR whitelist table with thermal/power MSR addresses. Otherwise zeroes the table (disabling MSR access).
- If `platform_id[0..3] == "MTCN"`, sets `g_ImcBarPhysAddr_MTCN = 0xFE0B05A6`; otherwise sets `g_ImcBarPhysAddr_Other = 0xFE0B05A6`.

**MSR whitelist set for CPU families 51/53/54:**

| Index | MSR Address | Intel Name | Description |
|---|---|---|---|
| 0 | `0x19B` (411) | IA32_THERM_INTERRUPT | Thermal interrupt enable/thresholds |
| 1 | `0x19C` (412) | IA32_THERM_STATUS | Current thermal status & temperature |
| 2 | `0x772` (1906) | IA32_HWP_CAPABILITIES | HWP min/max/guaranteed P-states (read-only on HW) |
| 3 | `0x774` (1908) | IA32_HWP_REQUEST | Per-core HWP performance hint |
| 4 | `0x65C` (1628) | MSR_PLATFORM_POWER_LIMIT | Package-level power limit (PL1/PL2) |
| 5 | `0x1B0` (432) | IA32_ENERGY_PERF_BIAS | Performance vs. energy-saving preference |

### IOCTL 0x9C4021C0 — Query DRAM Range Info
- **Input**: output buffer ≥ 16 bytes  
- **Output**: two QWORDs (DRAM channel base addresses, masked `& 0x7FFF`)  
- Reads PCI config space at bus 0, dev 0, func 0, offset `0x48` via `HalGetBusDataByOffset` to find the Intel IMC MMIO BAR. Adds offset `0x59A0`, maps 8 bytes with `MmMapIoSpace(MmNonCached)`, reads two QWORD values representing DRAM range addresses. Physical address is **not user-controlled**.

### IOCTL 0x9C4021CC — MSR Read (`Ioctl_MsrRead`)
- **Input**: `{ DWORD index; }` — selects MSR from whitelist (0–5)  
- **Output**: QWORD (8 bytes) containing the MSR value  
- Executes `RDMSR` via `__readmsr()` at the whitelisted address for the given index. Returns `STATUS_INVALID_PARAMETER` if index out of range or MSR address is zero (table not initialized).

### IOCTL 0x9C4021D0 — MSR Write (`Ioctl_MsrWrite`)
- **Input**: `{ DWORD index; QWORD value; }` — selects MSR + new value  
- **Output**: none  
- Executes `WRMSR` via `__writemsr()`. Index mapped identically to MSR Read.

### IOCTL 0x9C4021C4 — MMIO Read (`Ioctl_MmioRead`)
- **Input**: `{ DWORD selector; DWORD stride; DWORD count; }` (12 bytes, must equal `InputBufferLength`)  
- **Output**: `count × stride` bytes read from Intel IMC MMIO  
- `selector` 0 → reads from `g_ImcBarPhysAddr_MTCN` (`0xFE0B05A6`)  
- `selector` 1 → reads from `g_ImcBarPhysAddr_Other` (`0xFE0B05A6`)  
- `stride` must be 1 (byte), 2 (word), or 8 (dword copy)  
- Maps `count × stride` bytes with `MmMapIoSpace(MmNonCached)`, copies to output buffer, unmaps.

### IOCTL 0x9C4021C8 — MMIO Write (`Ioctl_MmioWrite`)
- **Input**: `{ DWORD selector; DWORD stride; DWORD count; BYTE data[count×stride]; }`  
- **Output**: none  
- Same physical address selection as MMIO Read. Writes `data[]` to the IMC MMIO region using `_InterlockedOr` as a memory fence after writes (ensures store ordering before unmap).

## Physical Address: Intel IMC MMIO at `0xFE0B05A6`

The hardcoded physical address `0xFE0B05A6` lies in the Intel Uncore (Integrated Memory Controller) MMIO register space, typically mapped just below 4 GB. This region contains IMC configuration registers for DRAM timing, channel interleaving, and thermal throttling — **not addressable RAM content**.

This address is **hardcoded in `Ioctl_InitCpuModel`** and is not user-controllable. `MmMapIoSpace` is called with this fixed address; the user can only control the `count` and `stride` (total mapping size).

## Vulnerability Assessment

### Arbitrary Physical Memory R/W?

**NO.**

The driver does not expose arbitrary physical address read or write:
- Physical addresses used for `MmMapIoSpace` are hardcoded (`0xFE0B05A6`) or derived from PCI config space (not user input).
- The user cannot pass a physical address to the driver.
- Only a fixed IMC MMIO region is accessible.

### MSR Arbitrary Write?

**NO — whitelisted only.**

The MSR addresses are stored in global variables populated by `Ioctl_InitCpuModel`. The user selects an MSR by index (0–5), which maps to a fixed set of thermal/power MSRs. There is no way to write to arbitrary MSRs (e.g., `IA32_LSTAR`, `IA32_SYSENTER_EIP`, `CR4` shadow, etc.).

### Access Control Bypass?

**Not directly.**

The device and FltMgr port are both SYSTEM-only. An unprivileged or admin process cannot open the device handle without prior escalation.

### Security Impact of Exposed Operations

If an attacker already has SYSTEM and can reach this driver (e.g., via a Lenovo service vulnerability), the following could be abused:

| Operation | Potential Impact |
|---|---|
| WRMSR `IA32_HWP_REQUEST` (0x774) | Force CPU into low-performance P-state (DoS of performance) |
| WRMSR `MSR_PLATFORM_POWER_LIMIT` (0x65C) | Lower package TDP limits (thermal DoS / performance degradation) |
| WRMSR `IA32_THERM_INTERRUPT` (0x19B) | Modify thermal interrupt thresholds |
| MMIO WRITE to IMC registers | Potentially corrupt IMC configuration (system instability) |

None of these directly grant code execution or ring-0 escalation from a SYSTEM-level attacker (who already has full control).

## Verdict

**NOT VULNERABLE to physical memory read/write from usermode.**

This driver is a legitimate Lenovo thermal/power management component. It exposes MSR read/write and Intel IMC MMIO access through a SYSTEM-only device, with operations restricted to a fixed whitelist of thermal and power management registers and a hardcoded physical MMIO address.

No PoC is warranted; there is no path from an unprivileged process to physical memory access through this driver.

## Key Functions (IDB)

| Address | Name | Description |
|---|---|---|
| `0x140009000` | `DriverEntry` | Entry point, calls `DriverEntry_Body` |
| `0x140002890` | `DriverEntry_Body` | Creates device, sets SDDL, registers dispatch |
| `0x1400012D0` | `FltMgr_RegisterAndCreatePort` | Registers FltMgr filter + communication port |
| `0x140001650` | `IrpDispatch_CreateCloseDeviceControl` | Main IRP handler (all device I/O) |
| `0x140001B00` | `FltMgr_MessageNotifyCallback` | FltMgr port message handler (no-op) |
| `0x140001BC0` | `Ioctl_InitCpuModel` | IOCTL 0x9C4021D4: init MSR table + IMC BAR |
| `0x1400021F0` | `Ioctl_MsrRead` | IOCTL 0x9C4021CC: RDMSR (whitelisted) |
| `0x140002710` | `Ioctl_MsrWrite` | IOCTL 0x9C4021D0: WRMSR (whitelisted) |
| `0x140002040` | `Ioctl_MmioRead` | IOCTL 0x9C4021C4: MMIO read via MmMapIoSpace |
| `0x140002540` | `Ioctl_MmioWrite` | IOCTL 0x9C4021C8: MMIO write via MmMapIoSpace |
| `0x140002390` | `PciConfigRead_DWORD` | HalGetBusDataByOffset wrapper |
| `0x140001D20` | `ProcessCreateNotifyRoutine` | PsSetCreateProcessNotifyRoutineEx callback |

## Analysis Methodology

1. Opened binary in IDA Pro (idalib headless), ran auto-analysis with Hex-Rays decompiler.
2. `survey_binary` identified FltMgr imports, `MmMapIoSpace`, `HalGetBusDataByOffset`, and MSR intrinsics as primary points of interest.
3. Decompiled all named and high-xref functions: `IrpDispatch_CreateCloseDeviceControl`, `FltMgr_MessageNotifyCallback`, `DriverEntry_Body`, `FltMgr_RegisterAndCreatePort`, and all IOCTL sub-handlers.
4. Traced physical address origin for all `MmMapIoSpace` calls — confirmed hardcoded or PCI-config-derived (not user-supplied).
5. Identified MSR whitelist population in `Ioctl_InitCpuModel` and verified index-based dispatch in `Ioctl_MsrRead`/`Ioctl_MsrWrite`.
6. Confirmed SYSTEM-only DACL from SDDL string and programmatic ACL construction in `FltMgr_RegisterAndCreatePort`.
7. Applied descriptive renames and comments to IDB; saved to `.i64`.
