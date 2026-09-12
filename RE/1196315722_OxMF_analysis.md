# Analysis: 1196315722_OxMF.sys

## Binary Metadata

| Field | Value |
|---|---|
| Filename | `1196315722_OxMF.sys` |
| Architecture | x86-64 (AMD64) |
| Image base | `0x10000` |
| Image size | `0xC000` |
| MD5 | `6dc933a43343695a90a850ac48fc2f09` |
| SHA-256 | `4ff07bbf716dce5b05fd434e28ef78142579606e349e9871687d9d2baf01d307` |
| Pool tag | `OxMF` (`0x4F784D46`) |
| Entry point | `DriverEntry` @ `0x19120` |

---

## Verdict: NO Physical R/W Vulnerability

**This driver does NOT expose arbitrary physical memory read or write to usermode applications.**

The driver is a legitimate **PnP bus enumerator** for **Oxford Semiconductor** multi-function serial/parallel port chips (OX16PCI95x family). All uses of `MmMapIoSpace`/`MmUnmapIoSpace` are strictly internal for hardware detection; no physical address or mapped pointer is ever returned to or controlled by usermode.

---

## Driver Identity

The pool tag `OxMF` and the hardware IDs embedded in `OxMF_CreateChildPDO` (`0x16C50`) confirm this is an **Oxford Semiconductor multi-function bus driver**. Child PDOs are created with hardware IDs such as:

- `OXMF\CF\*PNP0501` — Oxford serial port (16550-compatible)
- `OXPC\IMF9\*...` — Oxford serial port (enhanced)
- `OXPC\IMF\*PNP0501` — Oxford serial port (standard)

The driver acts as the FDO (Functional Device Object) for the parent Oxford chip and enumerates its child COM ports as PDOs.

---

## Dispatch Table (set in `OxMF_DriverInit` @ `0x19010`)

| IRP Major | Index | Handler | Address |
|---|---|---|---|
| IRP_MJ_CREATE | `MajorFunction[0]` | `OxMF_CreateClose` | `0x15010` |
| IRP_MJ_CLOSE | `MajorFunction[2]` | `OxMF_CreateClose` | `0x15010` |
| IRP_MJ_DEVICE_CONTROL | `MajorFunction[14]` | `OxMF_DeviceControl` | `0x11010` |
| IRP_MJ_POWER | `MajorFunction[22]` | `OxMF_DispatchPower` | `0x177D0` |
| IRP_MJ_SYSTEM_CONTROL | `MajorFunction[23]` | `OxMF_DispatchWMI` | `0x18730` |
| IRP_MJ_PNP | `MajorFunction[27]` | `OxMF_DispatchPnP` | `0x162A0` |
| DriverExtension→AddDevice | — | `OxMF_AddDevice` | `0x150B0` |
| DriverUnload | — | `Dns_EndDebug` (IDA label) | — |

---

## IOCTL Analysis (`OxMF_DeviceControl` @ `0x11010`)

The device control handler supports **exactly one IOCTL code**:

### IOCTL `0x1B40FC`

```
CTL_CODE(DeviceType=27, Function=63, Method=METHOD_BUFFERED, Access=FILE_READ_ACCESS)
```

**Behavior:**
1. Validates `IoControlCode == 0x1B40FC` — otherwise returns `STATUS_INVALID_DEVICE_REQUEST` (`0xC0000010`).
2. Validates output buffer length `>= 0xA18` (2584 bytes) — otherwise returns `STATUS_BUFFER_TOO_SMALL` (`0xC0000023`).
3. Validates the system buffer is present and has magic `0x01` at a specific offset.
4. Fills 2584 bytes of output with:
   - Magic version bytes (`0x01 0x02 0x03 0x04`)
   - A copy of the driver's `RegistryPath` (saved at load time into `DestinationString`)
   - Hardware configuration data from the device extension (chip type, port counts)
5. Sets `IoStatus.Information = 2584`, completes the IRP.

**No physical memory is read, written, or mapped through this IOCTL.**

---

## `MmMapIoSpace` Usage (Internal Only)

### `OxMF_ProbeUartPort` @ `0x11120`

Called from `OxMF_EnumerateChildren` during `IRP_MN_START_DEVICE`.

```
MmMapIoSpace(physAddr, 8, MmNonCached)  →  virtualPtr
```

- Maps **8 bytes** of the chip's I/O register range into kernel VA.
- Performs port I/O (`__inbyte`/`__outbyte`) at `CR8=0xF` (IRQL=HIGH_LEVEL) to detect the UART type (checks for response bytes `0x16`/`0xC9`).
- **Immediately unmaps** with `MmUnmapIoSpace(ptr, 8)`.
- Returns `1` (detected) or `0` (not detected).
- The physical address comes from the device's `CM_RESOURCE_LIST`, not from usermode.
- Result is a boolean stored in the driver's internal state. **Never returned to usermode.**

### `OxMF_ProbeMMIORegister` @ `0x114A0`

Called from `OxMF_FDO_DispatchPnP` during `IRP_MN_START_DEVICE`.

```
MmMapIoSpace(physAddr_from_devext, size_from_devext, MmNonCached)  →  virtualPtr
```

- Physical address and size are sourced from pre-parsed resource data in the device extension (filled by `OxMF_ParseResourceList` from the PnP resource list IRP).
- Reads one byte at `base + 15` to determine chip revision.
- **Immediately unmaps.**
- Result (a `HighPart` flag) is stored in the device extension. **Never returned to usermode.**

---

## Key Function Map

| Address | Name | Purpose |
|---|---|---|
| `0x19120` | `DriverEntry` | Security cookie init, calls `OxMF_DriverInit` |
| `0x19010` | `OxMF_DriverInit` | Copies RegistryPath, populates dispatch table |
| `0x150B0` | `OxMF_AddDevice` | Creates FDO, attaches to PDO stack, opens device registry |
| `0x15010` | `OxMF_CreateClose` | Handles IRP_MJ_CREATE and IRP_MJ_CLOSE (trivial complete) |
| `0x11010` | `OxMF_DeviceControl` | Single IOCTL 0x1B40FC — returns device identity |
| `0x162A0` | `OxMF_DispatchPnP` | PnP router: FDO path → `OxMF_FDO_DispatchPnP`, PDO path → `OxMF_PDO_DispatchPnP` |
| `0x15EF0` | `OxMF_FDO_DispatchPnP` | FDO PnP handler (start/stop/remove/query) |
| `0x16930` | `OxMF_PDO_DispatchPnP` | PDO PnP handler (child device lifecycle) |
| `0x153E0` | `OxMF_ParseResourceList` | Parses CM_RESOURCE_LIST from PnP start IRP, stores base addresses in FDO extension |
| `0x17150` | `OxMF_EnumerateChildren` | Detects child ports (calls `OxMF_ProbeUartPort`), creates PDOs via `OxMF_CreateChildPDO` |
| `0x16C50` | `OxMF_CreateChildPDO` | Creates a child PDO with Oxford hardware ID strings |
| `0x11120` | `OxMF_ProbeUartPort` | Maps 8 bytes of UART MMIO, probes via port I/O, unmaps |
| `0x114A0` | `OxMF_ProbeMMIORegister` | Maps chip MMIO registers, reads one byte, unmaps |
| `0x113C0` | `OxMF_ReadRegistryValue` | Reads a DWORD from a registry key into device extension |
| `0x11300` | `OxMF_AcquireMutex` | Wrapper: `ExAcquireFastMutex` on extension mutex |
| `0x11330` | `OxMF_ReleaseMutex` | Wrapper: `ExReleaseFastMutex` on extension mutex |
| `0x177D0` | `OxMF_DispatchPower` | IRP_MJ_POWER handler |
| `0x18730` | `OxMF_DispatchWMI` | IRP_MJ_SYSTEM_CONTROL — delegates to `WmiSystemControl` |
| `0x18970` | `OxMF_RegisterWMI` | Calls `IoWMIRegistrationControl` |
| `0x16520` | `OxMF_HandleQueryId` | IRP_MN_QUERY_ID — returns hardware/compatible ID strings |
| `0x16460` | `OxMF_HandleStartDevice` | PDO IRP_MN_START_DEVICE |
| `0x16B30` | `OxMF_BuildHardwareIdString` | Builds hardware ID string from chip type |
| `0x17A80` | `OxMF_SetupChipType_A` | Chip-specific init path A (chip type 0x95050000) |
| `0x17840` | `OxMF_SetupChipType_B` | Chip-specific init path B |

---

## Supported Chip IDs (from `OxMF_ProbeMMIORegister`)

The driver branches on the following hardware IDs (stored as DWORD in the device extension at `+0x20`):

| Constant (decimal) | Hex | Meaning |
|---|---|---|
| `-2080309248` | `0x84010000` | Oxford OX16PCI952 (dual serial) |
| `-1794899968` | `0x95040000` | Oxford OX16PCI954 (quad serial) |
| `-1794834432` | `0x95050000` | Oxford OX16PCI954B |
| `-1792999424` | `0x95210000` | Oxford OX16PCI952 variant |
| `-1791492096` | `0x95600000` | Oxford OX16PCI958 (octal serial) |
| `-1781596160` | `0x9C130000` | Oxford OX16PCI954 (another variant) |

---

## Why No Vulnerability

1. **Single narrow IOCTL**: `0x1B40FC` only returns a fixed device descriptor blob. There is no IOCTL for read/write/map operations on arbitrary physical addresses.
2. **Physical addresses not usermode-controlled**: All physical addresses passed to `MmMapIoSpace` come from the PnP `CM_RESOURCE_LIST` allocated by the kernel PnP manager — not from any usermode-supplied buffer.
3. **Mappings are ephemeral**: Both `OxMF_ProbeUartPort` and `OxMF_ProbeMMIORegister` map memory, use it, and immediately unmap it with `MmUnmapIoSpace`. No persistent mapping is kept.
4. **No mapped pointer is returned to usermode**: Neither the virtual address nor any data beyond a single status byte flows back to usermode via any IRP completion or IOCTL output.
5. **No `\Device\PhysicalMemory` access**: The import list contains no `ZwOpenSection`, `ZwMapViewOfSection`, or similar calls that would create a shareable physical memory section.
6. **Method-Buffered IOCTL**: The one supported IOCTL uses `METHOD_BUFFERED`, meaning the kernel copies data through a system buffer — there is no direct user buffer pointer manipulation.

---

## Methodology

1. Opened binary in IDA Pro via MCP, ran full auto-analysis with Hex-Rays.
2. Ran `survey_binary` to identify entry points, imports, and top functions by xref count.
3. Identified `MmMapIoSpace`/`MmUnmapIoSpace` as key imports; traced all call sites via `xrefs_to`.
4. Analyzed `DriverEntry` → `OxMF_DriverInit` to map the full dispatch table.
5. Analyzed `OxMF_DeviceControl` (IRP_MJ_DEVICE_CONTROL) — the sole usermode-facing attack surface.
6. Analyzed both `MmMapIoSpace` callers (`OxMF_ProbeUartPort`, `OxMF_ProbeMMIORegister`) to confirm no usermode data flow.
7. Analyzed PnP handlers (`OxMF_FDO_DispatchPnP`, `OxMF_PDO_DispatchPnP`) to understand device lifecycle.
8. Analyzed `OxMF_EnumerateChildren` and `OxMF_CreateChildPDO` to identify the hardware family (Oxford Semiconductor).
9. Renamed 24 functions and added 20 comments to the IDB.
10. Saved IDB to `.i64` file.
