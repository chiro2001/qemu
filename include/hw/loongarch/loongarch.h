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

#define LOONGARCH_MAX_VCPUS     4
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

typedef struct LoongArchMachineState {
    /*< private >*/
    MachineState parent_obj;

    AddressSpace *address_space_iocsr;
    MemoryRegion *system_iocsr;
} LoongArchMachineState;

#define TYPE_LOONGARCH_MACHINE  MACHINE_TYPE_NAME("loongson7a")
DECLARE_INSTANCE_CHECKER(LoongArchMachineState, LOONGARCH_MACHINE,
                         TYPE_LOONGARCH_MACHINE)
#endif
