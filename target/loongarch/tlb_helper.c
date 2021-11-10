/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU LoongArch TLB helpers for qemu
 *
 * Copyright (c) 2021 Loongson Technology Corporation Limited
 *
 */

#include "qemu/osdep.h"

#include "cpu.h"
#include "internals.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "exec/log.h"
#include "cpu-csr.h"

enum {
    TLBRET_MATCH = 0,
    TLBRET_BADADDR =1,
    TLBRET_NOMATCH = 2,
    TLBRET_INVALID = 3,
    TLBRET_DIRTY = 4,
    TLBRET_RI = 5,
    TLBRET_XI = 6,
    TLBRET_PE = 7,
};

/* TLB address map */
static int loongarch_map_tlb_entry(CPULoongArchState *env, hwaddr *physical,
                                   int *prot, target_ulong address,
                                   int access_type, loongarch_tlb *tlb)
{
    uint64_t plv = FIELD_EX64(env->CSR_CRMD, CSR_CRMD, PLV);
    uint8_t tlb_ps, n, tlb_v0, tlb_v1, tlb_d0, tlb_d1;
    uint8_t tlb_nx0, tlb_nx1, tlb_nr0, tlb_nr1;
    uint64_t tlb_ppn0, tlb_ppn1;
    uint8_t tlb_rplv0, tlb_rplv1, tlb_plv0, tlb_plv1;

    tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);
    n = (address >> tlb_ps) & 0x1;/* Odd or even */

    tlb_v0 = FIELD_EX64(tlb->tlb_entry0, ENTRY0, V);
    tlb_d0 = FIELD_EX64(tlb->tlb_entry0, ENTRY0, D);
    tlb_plv0 = FIELD_EX64(tlb->tlb_entry0, ENTRY0, PLV);
    tlb_ppn0 = FIELD_EX64(tlb->tlb_entry0, ENTRY0, PPN);
    tlb_nx0 = FIELD_EX64(tlb->tlb_entry0, ENTRY0, NX);
    tlb_nr0 = FIELD_EX64(tlb->tlb_entry0, ENTRY0, NR);
    tlb_rplv0 = FIELD_EX64(tlb->tlb_entry0, ENTRY0, RPLV);

    tlb_v1 = FIELD_EX64(tlb->tlb_entry1, ENTRY1, V);
    tlb_d1 = FIELD_EX64(tlb->tlb_entry1, ENTRY1, D);
    tlb_plv1 = FIELD_EX64(tlb->tlb_entry1, ENTRY1, PLV);
    tlb_ppn1 = FIELD_EX64(tlb->tlb_entry1, ENTRY1, PPN);
    tlb_nx1 = FIELD_EX64(tlb->tlb_entry1, ENTRY1, NX);
    tlb_nr1 = FIELD_EX64(tlb->tlb_entry1, ENTRY1, NR);
    tlb_rplv1 = FIELD_EX64(tlb->tlb_entry1, ENTRY1, RPLV);

    /* Check access rights */
    if (!(n ? tlb_v1 : tlb_v0)) {
        return TLBRET_INVALID;
    }

    if (access_type == MMU_INST_FETCH && (n ? tlb_nx1 : tlb_nx0)) {
        return TLBRET_XI;
    }

    if (access_type == MMU_DATA_LOAD && (n ? tlb_nr1 : tlb_nr0)) {
        return TLBRET_RI;
    }

    if (n) {
        if (((tlb_rplv1 == 0) && (plv > tlb_plv1)) ||
            ((tlb_rplv1 == 1) && (plv != tlb_plv1))) {
            return TLBRET_PE;
        }
    } else {
        if (((tlb_rplv0 == 0) && (plv > tlb_plv0)) ||
            ((tlb_rplv0 == 1) && (plv != tlb_plv0))) {
            return TLBRET_PE;
        }
    }

    if ((access_type == MMU_DATA_STORE) && !(n ? tlb_d1 : tlb_d0)) {
        return TLBRET_DIRTY;
    }

    /*
     *         PPN     address
     *  4 KB: [47:13]   [12;0]
     * 16 KB: [47:15]   [14:0]
     */
    if (n) {
        *physical = (tlb_ppn1 << 12) | (address & ((1 << tlb_ps) - 1));
    } else {
        *physical = (tlb_ppn0 << 12) | (address & ((1 << tlb_ps) - 1));
    }
    *prot = PAGE_READ;
    if (n ? tlb_d1 : tlb_d0) {
        *prot |= PAGE_WRITE;
    }
    if (!(n ? tlb_nx1 : tlb_nx0)) {
        *prot |= PAGE_EXEC;
    }
    return TLBRET_MATCH;
}

/* LoongArch 3A5000 -style MMU emulation */
static int loongarch_map_address(CPULoongArchState *env, hwaddr *physical,
                                 int *prot,
                                 target_ulong address,
                                 MMUAccessType access_type)
{
    loongarch_tlb *tlb;
    uint16_t csr_asid, tlb_asid, stlb_idx;
    uint8_t tlb_e, stlb_ps, tlb_ps, tlb_g;
    int i, stlb_size, mtlb_size;
    uint64_t vpn, tlb_vppn;   /* Address to map */

    stlb_size = env->stlb_size;
    mtlb_size = env->mtlb_size;
    csr_asid = FIELD_EX64(env->CSR_ASID, CSR_ASID, ASID);

    /* Search MTLB */
    for (i = stlb_size; i < stlb_size + mtlb_size; ++i) {
        tlb = &env->tlb[i];
        tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
        tlb_ps = FIELD_EX64(tlb->tlb_misc, TLB_MISC, PS);

        vpn = (address & TARGET_VIRT_MASK) >> (tlb_ps + 1);
        tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        tlb_g = FIELD_EX64(tlb->tlb_misc, TLB_MISC, G);

        if ((tlb_g == 1 || tlb_asid == csr_asid) &&
            (vpn == (tlb_vppn >> (tlb_ps + 1 - 13))) && tlb_e) {
            return loongarch_map_tlb_entry(env, physical, prot,
                                                   address, access_type, tlb);
        }
    }

    /* Search STLB */
    stlb_ps = FIELD_EX64(env->CSR_STLBPS, CSR_STLBPS, PS);
    vpn = (address & TARGET_VIRT_MASK) >> (stlb_ps + 1);

    /* VA[ps+11 : ps+1] indicate the stlb index */
    stlb_idx = vpn & 0xff; /* [0,255] */

    for (i = 0; i < 8; ++i) {
        tlb = &env->tlb[i * 256 + stlb_idx];
        tlb_vppn = FIELD_EX64(tlb->tlb_misc, TLB_MISC, VPPN);
        tlb_asid = FIELD_EX64(tlb->tlb_misc, TLB_MISC, ASID);
        tlb_e = FIELD_EX64(tlb->tlb_misc, TLB_MISC, E);
        tlb_g = FIELD_EX64(tlb->tlb_misc, TLB_MISC, G);

        if ((tlb_g == 1 || tlb_asid == csr_asid) &&
            (vpn == (tlb_vppn >> (stlb_ps + 1 - 13))) && tlb_e) {
            return loongarch_map_tlb_entry(env, physical, prot,
                                                   address, access_type, tlb);
        }
    }

    return TLBRET_NOMATCH;
}

static int get_physical_address(CPULoongArchState *env, hwaddr *physical,
                                int *prot, target_ulong real_address,
                                MMUAccessType access_type, int mmu_idx)
{
    int user_mode = mmu_idx == LOONGARCH_HFLAG_UM;
    int kernel_mode = !user_mode;
    unsigned plv, base_c, base_v, tmp;
    uint64_t pg = FIELD_EX64(env->CSR_CRMD, CSR_CRMD, PG);

    /* Effective address */
    target_ulong address = real_address;

    /* Check PG */
    if (!pg) {
        /* DA mode */
        *physical = address & TARGET_PHYS_MASK;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TLBRET_MATCH;
    }

    plv = kernel_mode | (user_mode << 3);
    base_v = address >> TARGET_VIRT_ADDR_SPACE_BITS;
    /* Check direct map window 0 */
    base_c = env->CSR_DMWIN0 >> TARGET_VIRT_ADDR_SPACE_BITS;
    if ((plv & env->CSR_DMWIN0) && (base_c == base_v)) {
        *physical = dmwin_va2pa(address);
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TLBRET_MATCH;
    }
    /* Check direct map window 1 */
    base_c = env->CSR_DMWIN1 >> TARGET_VIRT_ADDR_SPACE_BITS;
    if ((plv & env->CSR_DMWIN1) && (base_c == base_v)) {
        *physical = dmwin_va2pa(address);
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        return TLBRET_MATCH;
    }
    /* Check valid extension */
    tmp = address >> (TARGET_VIRT_ADDR_SPACE_BITS - 1);
    if (!(tmp == 0 || tmp == 0x1ffff)) {
        return TLBRET_BADADDR;
    }
    /* Mapped address */
    return loongarch_map_address(env, physical, prot, real_address,
                                 access_type);
}

hwaddr loongarch_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    LoongArchCPU *cpu = LOONGARCH_CPU(cs);
    CPULoongArchState *env = &cpu->env;
    hwaddr phys_addr;
    int prot;

    if (get_physical_address(env, &phys_addr, &prot, addr, MMU_DATA_LOAD,
                             cpu_mmu_index(env, false)) != 0) {
        return -1;
    }
    return phys_addr;
}

static void raise_mmu_exception(CPULoongArchState *env, target_ulong address,
                                MMUAccessType access_type, int tlb_error)
{
    CPUState *cs = env_cpu(env);

    switch (tlb_error) {
    default:
    case TLBRET_BADADDR:
        cs->exception_index = EXCP_ADE;
        break;
    case TLBRET_NOMATCH:
        /* No TLB match for a mapped address */
        if (access_type == MMU_DATA_LOAD) {
            cs->exception_index = EXCP_TLBL;
        } else if (access_type == MMU_DATA_STORE) {
            cs->exception_index = EXCP_TLBS;
        } else if (access_type == MMU_INST_FETCH) {
            cs->exception_index = EXCP_INST_NOTAVAIL;
        }
        env->CSR_TLBRERA = FIELD_DP64(env->CSR_TLBRERA, CSR_TLBRERA, ISTLBR, 1);
        break;
    case TLBRET_INVALID:
        /* TLB match with no valid bit */
        if (access_type == MMU_DATA_LOAD) {
            cs->exception_index = EXCP_TLBL;
        } else if (access_type == MMU_DATA_STORE) {
            cs->exception_index = EXCP_TLBS;
        } else if (access_type == MMU_INST_FETCH) {
            cs->exception_index = EXCP_INST_NOTAVAIL;
        }
        break;
    case TLBRET_DIRTY:
        /* TLB match but 'D' bit is cleared */
        cs->exception_index = EXCP_TLBM;
        break;
    case TLBRET_XI:
        /* Execute-Inhibit Exception */
        cs->exception_index = EXCP_TLBNX;
        break;
    case TLBRET_RI:
        /* Read-Inhibit Exception */
        cs->exception_index = EXCP_TLBNR;
        break;
    case TLBRET_PE:
        /* Privileged Exception */
        cs->exception_index = EXCP_TLBPE;
        break;
    }

    if (tlb_error == TLBRET_NOMATCH) {
        env->CSR_TLBRBADV = address;
        env->CSR_TLBREHI = address & (TARGET_PAGE_MASK << 1);
    } else {
        if (!FIELD_EX64(env->CSR_DBG, CSR_DBG, DST)) {
            env->CSR_BADV = address;
        }
        env->CSR_TLBEHI = address & (TARGET_PAGE_MASK << 1);
   }

}

void loongarch_mmu_init(CPULoongArchState *env)
{
    /* Number of MTLB */
    env->mtlb_size = 64;

    /* Number of STLB */
    env->stlb_size = 2048;

    /* For 16KB, ps = 14, compare the bit [47:15] */
    for (int i = 0; i < LOONGARCH_TLB_MAX; i++) {
        env->tlb[i].tlb_misc = FIELD_DP64(env->tlb[i].tlb_misc, TLB_MISC, E, 0);
    }
}

bool loongarch_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                            MMUAccessType access_type, int mmu_idx,
                            bool probe, uintptr_t retaddr)
{
    LoongArchCPU *cpu = LOONGARCH_CPU(cs);
    CPULoongArchState *env = &cpu->env;
    hwaddr physical;
    int prot;
    int ret = TLBRET_BADADDR;

    /* Data access */
    /* XXX: put correct access by using cpu_restore_state() correctly */
    ret = get_physical_address(env, &physical, &prot, address,
                               access_type, mmu_idx);
    switch (ret) {
    case TLBRET_MATCH:
        qemu_log_mask(CPU_LOG_MMU,
                      "%s address=%" VADDR_PRIx " physical " TARGET_FMT_plx
                      " prot %d\n", __func__, address, physical, prot);
        break;
    default:
        qemu_log_mask(CPU_LOG_MMU,
                      "%s address=%" VADDR_PRIx " ret %d\n", __func__, address,
                      ret);
        break;
    }
    if (ret == TLBRET_MATCH) {
        tlb_set_page(cs, address & TARGET_PAGE_MASK,
                     physical & TARGET_PAGE_MASK, prot,
                     mmu_idx, TARGET_PAGE_SIZE);
        return true;
    }
    if (probe) {
        return false;
    } else {
        raise_mmu_exception(env, address, access_type, ret);
        do_raise_exception(env, cs->exception_index, retaddr);
    }
}
