/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LoongArch ipi interrupt header files
 *
 * Copyright (C) 2021 Loongson Technology Corporation Limited
 */

#ifndef HW_LOONGARCH_GIPI_H
#define HW_LOONGARCH_GIPI_H

#define SMP_GIPI_MAILBOX      0x1000ULL
#define CORE_STATUS_OFF       0x0
#define CORE_EN_OFF           0x4
#define CORE_SET_OFF          0x8
#define CORE_CLEAR_OFF        0xc
#define CORE_BUF_20           0x20
#define CORE_BUF_28           0x28
#define CORE_BUF_30           0x30
#define CORE_BUF_38           0x38

#define MAX_GIPI_CORE_NUM      4
#define MAX_GIPI_MBX_NUM       4

typedef struct gipi_core {
    uint32_t status;
    uint32_t en;
    uint32_t set;
    uint32_t clear;
    uint64_t buf[MAX_GIPI_MBX_NUM];
    qemu_irq irq;
} gipi_core;

typedef struct gipiState {
    gipi_core core[MAX_GIPI_CORE_NUM];
} gipiState;

#endif
