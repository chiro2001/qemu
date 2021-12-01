/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * LoongArch emulation helpers for csr registers
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "internals.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "hw/irq.h"
#include "cpu-csr.h"
#include "hw/loongarch/loongarch.h"
#include "tcg/tcg-ldst.h"

target_ulong helper_csr_rdq(CPULoongArchState *env, uint64_t csr)
{
    int64_t v;

    switch (csr) {
    case LOONGARCH_CSR_PGD:
        if (env->CSR_TLBRERA & 0x1) {
            v = env->CSR_TLBRBADV;
        } else {
            v = env->CSR_BADV;
        }

        if ((v >> 63) & 0x1) {
            v = env->CSR_PGDH;
        } else {
            v = env->CSR_PGDL;
        }
        v = v & TARGET_PHYS_MASK;
        break;
    case LOONGARCH_CSR_CPUID:
        v = (env_cpu(env))->cpu_index;
        break;
    case LOONGARCH_CSR_TVAL:
        v = cpu_loongarch_get_stable_timer_ticks(env);
        break;
    default:
        assert(0);
    }

    return v;
}

target_ulong helper_csr_wrq(CPULoongArchState *env, target_ulong val,
                            uint64_t csr)
{
    int64_t old_v;
    old_v = -1;

    switch (csr) {
    case LOONGARCH_CSR_ASID:
        old_v = env->CSR_ASID;
        env->CSR_ASID = val;
        if (old_v != val) {
            tlb_flush(env_cpu(env));
        }
        break;
    case LOONGARCH_CSR_TCFG:
        old_v = env->CSR_TCFG;
        cpu_loongarch_store_stable_timer_config(env, val);
        break;
    case LOONGARCH_CSR_TINTCLR:
        old_v = 0;
        qemu_irq_lower(env->irq[IRQ_TIMER]);
        break;
    default:
        assert(0);
    }

    return old_v;
}

target_ulong helper_csr_xchgq(CPULoongArchState *env, target_ulong val,
                              target_ulong mask, uint64_t csr)
{
    target_ulong tmp;
    target_ulong v = val & mask;

#define CASE_CSR_XCHGQ(csr)                                 \
    case LOONGARCH_CSR_ ## csr:                             \
    {                                                       \
        val = env->CSR_ ## csr;                             \
        env->CSR_ ## csr = (env->CSR_ ## csr) & (~mask);    \
        env->CSR_ ## csr = (env->CSR_ ## csr) | v;          \
        break;                                              \
    };                                                      \

    switch (csr) {
    CASE_CSR_XCHGQ(CRMD)
    CASE_CSR_XCHGQ(PRMD)
    CASE_CSR_XCHGQ(EUEN)
    CASE_CSR_XCHGQ(MISC)
    CASE_CSR_XCHGQ(ECFG)
    CASE_CSR_XCHGQ(ESTAT)
    CASE_CSR_XCHGQ(ERA)
    CASE_CSR_XCHGQ(BADV)
    CASE_CSR_XCHGQ(BADI)
    CASE_CSR_XCHGQ(EENTRY)
    CASE_CSR_XCHGQ(TLBIDX)
    CASE_CSR_XCHGQ(TLBEHI)
    CASE_CSR_XCHGQ(TLBELO0)
    CASE_CSR_XCHGQ(TLBELO1)
    CASE_CSR_XCHGQ(ASID)
    CASE_CSR_XCHGQ(PGDL)
    CASE_CSR_XCHGQ(PGDH)
    CASE_CSR_XCHGQ(PGD)
    CASE_CSR_XCHGQ(PWCL)
    CASE_CSR_XCHGQ(PWCH)
    CASE_CSR_XCHGQ(STLBPS)
    CASE_CSR_XCHGQ(RVACFG)
    CASE_CSR_XCHGQ(CPUID)
    CASE_CSR_XCHGQ(PRCFG1)
    CASE_CSR_XCHGQ(PRCFG2)
    CASE_CSR_XCHGQ(PRCFG3)
    CASE_CSR_XCHGQ(SAVE0)
    CASE_CSR_XCHGQ(SAVE1)
    CASE_CSR_XCHGQ(SAVE2)
    CASE_CSR_XCHGQ(SAVE3)
    CASE_CSR_XCHGQ(SAVE4)
    CASE_CSR_XCHGQ(SAVE5)
    CASE_CSR_XCHGQ(SAVE6)
    CASE_CSR_XCHGQ(SAVE7)
    CASE_CSR_XCHGQ(TMID)
    case LOONGARCH_CSR_TCFG:
        val = env->CSR_TCFG;
        tmp = val & ~mask;
        tmp |= v;
        cpu_loongarch_store_stable_timer_config(env, tmp);
        break;
    CASE_CSR_XCHGQ(TVAL)
    CASE_CSR_XCHGQ(CNTC)
    CASE_CSR_XCHGQ(TINTCLR)
    CASE_CSR_XCHGQ(LLBCTL)
    CASE_CSR_XCHGQ(IMPCTL1)
    CASE_CSR_XCHGQ(IMPCTL2)
    CASE_CSR_XCHGQ(TLBRENTRY)
    CASE_CSR_XCHGQ(TLBRBADV)
    CASE_CSR_XCHGQ(TLBRERA)
    CASE_CSR_XCHGQ(TLBRSAVE)
    CASE_CSR_XCHGQ(TLBRELO0)
    CASE_CSR_XCHGQ(TLBRELO1)
    CASE_CSR_XCHGQ(TLBREHI)
    CASE_CSR_XCHGQ(TLBRPRMD)
    CASE_CSR_XCHGQ(MERRCTL)
    CASE_CSR_XCHGQ(MERRINFO)
    CASE_CSR_XCHGQ(MERRINFO1)
    CASE_CSR_XCHGQ(MERRENT)
    CASE_CSR_XCHGQ(MERRERA)
    CASE_CSR_XCHGQ(MERRSAVE)
    CASE_CSR_XCHGQ(CTAG)
    CASE_CSR_XCHGQ(DMWIN0)
    CASE_CSR_XCHGQ(DMWIN1)
    CASE_CSR_XCHGQ(DMWIN2)
    CASE_CSR_XCHGQ(DMWIN3)
    CASE_CSR_XCHGQ(PERFCTRL0)
    CASE_CSR_XCHGQ(PERFCNTR0)
    CASE_CSR_XCHGQ(PERFCTRL1)
    CASE_CSR_XCHGQ(PERFCNTR1)
    CASE_CSR_XCHGQ(PERFCTRL2)
    CASE_CSR_XCHGQ(PERFCNTR2)
    CASE_CSR_XCHGQ(PERFCTRL3)
    CASE_CSR_XCHGQ(PERFCNTR3)
    /* debug */
    CASE_CSR_XCHGQ(MWPC)
    CASE_CSR_XCHGQ(MWPS)
    CASE_CSR_XCHGQ(DB0ADDR)
    CASE_CSR_XCHGQ(DB0MASK)
    CASE_CSR_XCHGQ(DB0CTL)
    CASE_CSR_XCHGQ(DB0ASID)
    CASE_CSR_XCHGQ(DB1ADDR)
    CASE_CSR_XCHGQ(DB1MASK)
    CASE_CSR_XCHGQ(DB1CTL)
    CASE_CSR_XCHGQ(DB1ASID)
    CASE_CSR_XCHGQ(DB2ADDR)
    CASE_CSR_XCHGQ(DB2MASK)
    CASE_CSR_XCHGQ(DB2CTL)
    CASE_CSR_XCHGQ(DB2ASID)
    CASE_CSR_XCHGQ(DB3ADDR)
    CASE_CSR_XCHGQ(DB3MASK)
    CASE_CSR_XCHGQ(DB3CTL)
    CASE_CSR_XCHGQ(DB3ASID)
    CASE_CSR_XCHGQ(FWPC)
    CASE_CSR_XCHGQ(FWPS)
    CASE_CSR_XCHGQ(IB0ADDR)
    CASE_CSR_XCHGQ(IB0MASK)
    CASE_CSR_XCHGQ(IB0CTL)
    CASE_CSR_XCHGQ(IB0ASID)
    CASE_CSR_XCHGQ(IB1ADDR)
    CASE_CSR_XCHGQ(IB1MASK)
    CASE_CSR_XCHGQ(IB1CTL)
    CASE_CSR_XCHGQ(IB1ASID)
    CASE_CSR_XCHGQ(IB2ADDR)
    CASE_CSR_XCHGQ(IB2MASK)
    CASE_CSR_XCHGQ(IB2CTL)
    CASE_CSR_XCHGQ(IB2ASID)
    CASE_CSR_XCHGQ(IB3ADDR)
    CASE_CSR_XCHGQ(IB3MASK)
    CASE_CSR_XCHGQ(IB3CTL)
    CASE_CSR_XCHGQ(IB3ASID)
    CASE_CSR_XCHGQ(IB4ADDR)
    CASE_CSR_XCHGQ(IB4MASK)
    CASE_CSR_XCHGQ(IB4CTL)
    CASE_CSR_XCHGQ(IB4ASID)
    CASE_CSR_XCHGQ(IB5ADDR)
    CASE_CSR_XCHGQ(IB5MASK)
    CASE_CSR_XCHGQ(IB5CTL)
    CASE_CSR_XCHGQ(IB5ASID)
    CASE_CSR_XCHGQ(IB6ADDR)
    CASE_CSR_XCHGQ(IB6MASK)
    CASE_CSR_XCHGQ(IB6CTL)
    CASE_CSR_XCHGQ(IB6ASID)
    CASE_CSR_XCHGQ(IB7ADDR)
    CASE_CSR_XCHGQ(IB7MASK)
    CASE_CSR_XCHGQ(IB7CTL)
    CASE_CSR_XCHGQ(IB7ASID)
    CASE_CSR_XCHGQ(DBG)
    CASE_CSR_XCHGQ(DERA)
    CASE_CSR_XCHGQ(DESAVE)
    default :
        assert(0);
    }

#undef CASE_CSR_XCHGQ
    return val;
}

/*
 * For per core address 0x10xx(IPI) 0x18xx(EXTIOI)
 * need extra adjust the iocsr addr.
 */
uint64_t helper_iocsr_read(CPULoongArchState *env, target_ulong r_addr,
                           uint32_t size)
{
    LoongArchMachineState *lams = LOONGARCH_MACHINE(qdev_get_machine());
    int cpuid = env_cpu(env)->cpu_index;
    target_ulong node_addr = (target_ulong)(cpuid & 0x3c) << 42;
    

    if (((r_addr & 0xff00) == 0x1000) || ((r_addr & 0xff00) == 0x1800)) {
        r_addr = r_addr + ((target_ulong)(cpuid & 0x3) << 8) + node_addr;
    } else if (((r_addr & 0xf000) == 0x1000)) {
        r_addr = r_addr + node_addr;
    }

    if (size == 1) {
        return address_space_ldub(lams->address_space_iocsr, r_addr,
                                  MEMTXATTRS_UNSPECIFIED, NULL);
    } else if (size == 2) {
        return address_space_lduw(lams->address_space_iocsr, r_addr,
                                  MEMTXATTRS_UNSPECIFIED, NULL);
    } else if (size == 4) {
        return address_space_ldl(lams->address_space_iocsr, r_addr,
                                 MEMTXATTRS_UNSPECIFIED, NULL);
    } else if (size == 8) {
        return address_space_ldq(lams->address_space_iocsr, r_addr,
                                 MEMTXATTRS_UNSPECIFIED, NULL);
    }
    return 0;
}

void helper_iocsr_write(CPULoongArchState *env, target_ulong w_addr,
                        target_ulong val, uint32_t size)
{
    LoongArchMachineState *lams = LOONGARCH_MACHINE(qdev_get_machine());
    int cpuid = env_cpu(env)->cpu_index;
    int mask, i;
    target_ulong node_addr;

    /*
     * For IPI send, Mail send, ANY send adjust addr and val
     * according to their real meaning
     */
    if (w_addr == 0x1040) { /* IPI send */
        cpuid = (val >> 16) & 0x3ff;
        val = 1UL << (val & 0x1f);
        w_addr = 0x1008;
    } else if (w_addr == 0x1048) { /* Mail Send */
        cpuid = (val >> 16) & 0x3ff;
        w_addr = 0x1020 + (val & 0x1c);
        val = val >> 32;
        mask = (val >> 27) & 0xf;
        size = 4;
    } else if (w_addr == 0x1158) { /* ANY send */
        cpuid = (val >> 16) & 0x3ff;
        w_addr = val & 0xffff;
        val = val >> 32;
        mask = (val >> 27) & 0xf;
        size = 1;
        node_addr = ((target_ulong)(cpuid & 0x3c) << 42);

        for (i = 0; i < 4; i++) {
            if (!((mask >> i) & 1)) {
                address_space_stb(lams->address_space_iocsr, w_addr + node_addr,
                                  val, MEMTXATTRS_UNSPECIFIED, NULL);
            }
            w_addr = w_addr + 1;
            val = val >> 8;
        }
        return;
    }

    node_addr = (target_ulong)(cpuid & 0x3c) << 42;
    if (((w_addr & 0xff00) == 0x1000) || ((w_addr & 0xff00) == 0x1800)) {
        w_addr = w_addr + ((target_ulong)(cpuid & 0x3) << 8) + node_addr;
    } else if (((w_addr & 0xf000) == 0x1000)) {
        w_addr = w_addr + node_addr;
    }

    if (size == 1) {
        address_space_stb(lams->address_space_iocsr, w_addr,
                          val, MEMTXATTRS_UNSPECIFIED, NULL);
    } else if (size == 2) {
        address_space_stw(lams->address_space_iocsr, w_addr,
                          val, MEMTXATTRS_UNSPECIFIED, NULL);
    } else if (size == 4) {
        address_space_stl(lams->address_space_iocsr, w_addr,
                          val, MEMTXATTRS_UNSPECIFIED, NULL);
    } else if (size == 8) {
        address_space_stq(lams->address_space_iocsr, w_addr,
                          val, MEMTXATTRS_UNSPECIFIED, NULL);
    }
}
