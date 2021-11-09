/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Definitions for loongarch board emulation.
 *
 * Copyright (C) 2021 Loongson Technology Corporation Limited
 */

#ifndef HW_LOONGARCH_H
#define HW_LOONGARCH_H

#include "target/loongarch/cpu.h"
#include "qemu-common.h"
#include "hw/boards.h"
#include "qemu/queue.h"
#include "hw/loongarch/gipi.h"

#define LOONGARCH_MAX_VCPUS     16
#define PM_MMIO_ADDR            0x10080000UL
#define PM_MMIO_SIZE            0x100
#define PM_CNT_MODE             0x10
#define FEATURE_REG             0x8
#define IOCSRF_TEMP             0
#define IOCSRF_NODECNT          1
#define IOCSRF_MSI              2
#define IOCSRF_EXTIOI           3
#define IOCSRF_CSRIPI           4
#define IOCSRF_FREQCSR          5
#define IOCSRF_FREQSCALE        6
#define IOCSRF_DVFSV1           7
#define IOCSRF_GMOD             9
#define IOCSRF_VM               11

#define VENDOR_REG              0x10
#define CPUNAME_REG             0x20

#define FW_CFG_ADDR             0x1e020000
#define LA_BIOS_BASE            0x1c000000
#define LA_BIOS_SIZE            (4 * 1024 * 1024)

/* Kernels can be configured with 64KB pages */
#define INITRD_PAGE_SIZE        (64 * KiB)
#define INITRD_BASE             0x04000000
#define COMMAND_LINE_SIZE       4096

#define LOONGARCH_NODE_SHIFT    44
/* Memory types: */
#define SYSTEM_RAM              1
#define SYSTEM_RAM_RESERVED     2
#define ACPI_TABLE              3
#define ACPI_NVS                4
#define SYSTEM_PMEM             5

typedef struct LoongArchMachineState {
    /*< private >*/
    MachineState parent_obj;

    AddressSpace *address_space_iocsr;
    MemoryRegion *system_iocsr;

    /* State for other subsystems/APIs: */
    Notifier machine_done;
    gipiState   *gipi;
    qemu_irq    *pch_irq;
    FWCfgState  *fw_cfg;
    OnOffAuto   acpi;
    char        *oem_id;
    char        *oem_table_id;
} LoongArchMachineState;

#define TYPE_LOONGARCH_MACHINE  MACHINE_TYPE_NAME("loongson7a")
DECLARE_INSTANCE_CHECKER(LoongArchMachineState, LOONGARCH_MACHINE,
                         TYPE_LOONGARCH_MACHINE)

void cpu_loongarch_init_irq(LoongArchCPU *cpu);
int cpu_init_ipi(LoongArchMachineState *lams, qemu_irq irq, int cpu);
bool loongarch_is_acpi_enabled(LoongArchMachineState *lams);
void loongarch_acpi_setup(LoongArchMachineState *lams);
#endif
