// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Shim providing Linux BPF kernel-ABI constants for the Fuchsia eBPF crate.
// Values are from include/linux/bpf_common.h and include/uapi/linux/bpf.h (Linux 6.x).
// These are stable kernel-ABI; they never change between kernel versions.
#![allow(non_upper_case_globals, dead_code)]

// --- BPF instruction classes ---
pub const BPF_LD: u32    = 0x00;
pub const BPF_LDX: u32   = 0x01;
pub const BPF_ST: u32    = 0x02;
pub const BPF_STX: u32   = 0x03;
pub const BPF_ALU: u32   = 0x04;
pub const BPF_JMP: u32   = 0x05;
pub const BPF_RET: u32   = 0x06;   // cBPF only
pub const BPF_MISC: u32  = 0x07;   // cBPF only
pub const BPF_ALU64: u32 = 0x07;   // eBPF (same encoding as MISC)
pub const BPF_JMP32: u32 = 0x06;   // eBPF (same encoding as RET)

// --- Source operand modifier ---
pub const BPF_K: u32 = 0x00;
pub const BPF_X: u32 = 0x08;

// --- Addressing / mode bits ---
pub const BPF_IMM: u32    = 0x00;
pub const BPF_ABS: u32    = 0x20;
pub const BPF_IND: u32    = 0x40;
pub const BPF_MEM: u32    = 0x60;
pub const BPF_LEN: u32    = 0x80;   // cBPF only
pub const BPF_MSH: u32    = 0xa0;   // cBPF only
pub const BPF_ATOMIC: u32 = 0xc0;   // eBPF only

// --- Operand width bits ---
pub const BPF_W: u32  = 0x00;
pub const BPF_H: u32  = 0x08;
pub const BPF_B: u32  = 0x10;
pub const BPF_DW: u32 = 0x18;

// --- Endianness (for BPF_ALU | BPF_END) ---
pub const BPF_TO_LE: u32 = 0x00;   // = BPF_K
pub const BPF_TO_BE: u32 = 0x08;   // = BPF_X

// --- ALU / JMP operation codes ---
pub const BPF_ADD: u32  = 0x00;
pub const BPF_SUB: u32  = 0x10;
pub const BPF_MUL: u32  = 0x20;
pub const BPF_DIV: u32  = 0x30;
pub const BPF_OR: u32   = 0x40;
pub const BPF_AND: u32  = 0x50;
pub const BPF_LSH: u32  = 0x60;
pub const BPF_RSH: u32  = 0x70;
pub const BPF_NEG: u32  = 0x80;
pub const BPF_MOD: u32  = 0x90;
pub const BPF_XOR: u32  = 0xa0;
pub const BPF_MOV: u32  = 0xb0;
pub const BPF_ARSH: u32 = 0xc0;
pub const BPF_END: u32  = 0xd0;

// --- Jump codes ---
pub const BPF_JA: u32   = 0x00;
pub const BPF_JEQ: u32  = 0x10;
pub const BPF_JGT: u32  = 0x20;
pub const BPF_JGE: u32  = 0x30;
pub const BPF_JSET: u32 = 0x40;
pub const BPF_JNE: u32  = 0x50;
pub const BPF_JSGT: u32 = 0x60;
pub const BPF_JSGE: u32 = 0x70;
pub const BPF_CALL: u32 = 0x80;
pub const BPF_EXIT: u32 = 0x90;
pub const BPF_JLT: u32  = 0xa0;
pub const BPF_JLE: u32  = 0xb0;
pub const BPF_JSLT: u32 = 0xc0;
pub const BPF_JSLE: u32 = 0xd0;

// --- cBPF misc / return helpers ---
pub const BPF_A: u32   = 0x10;
pub const BPF_TAX: u32 = 0x00;
pub const BPF_TXA: u32 = 0x80;

// --- Atomic sub-operations ---
pub const BPF_FETCH: u32    = 0x01;
pub const BPF_XCHG: u32     = 0xe0 | BPF_FETCH;  // 0xe1
pub const BPF_CMPXCHG: u32  = 0xf0 | BPF_FETCH;  // 0xf1

// --- BPF_CALL pseudo src_reg values ---
pub const BPF_PSEUDO_CALL: u32       = 1;
pub const BPF_PSEUDO_KFUNC_CALL: u32 = 2;

// --- BPF_LD | BPF_DW | BPF_IMM (LDDW) pseudo src values ---
pub const BPF_PSEUDO_MAP_FD: u32        = 1;
pub const BPF_PSEUDO_MAP_VALUE: u32     = 2;
pub const BPF_PSEUDO_BTF_ID: u32        = 3;
pub const BPF_PSEUDO_FUNC: u32          = 4;
pub const BPF_PSEUDO_MAP_IDX: u32       = 5;
pub const BPF_PSEUDO_MAP_IDX_VALUE: u32 = 6;

// --- Map creation flags (BPF_MAP_CREATE attr.map_flags) ---
pub const BPF_F_NO_PREALLOC: u32      = 1 << 0;
pub const BPF_F_NO_COMMON_LRU: u32   = 1 << 1;
pub const BPF_F_NUMA_NODE: u32       = 1 << 2;
pub const BPF_F_RDONLY: u32          = 1 << 3;
pub const BPF_F_WRONLY: u32          = 1 << 4;
pub const BPF_F_STACK_BUILD_ID: u32  = 1 << 5;
pub const BPF_F_ZERO_SEED: u32       = 1 << 6;
pub const BPF_F_RDONLY_PROG: u32     = 1 << 7;
pub const BPF_F_WRONLY_PROG: u32     = 1 << 8;
pub const BPF_F_CLONE: u32           = 1 << 9;
pub const BPF_F_MMAPABLE: u32        = 1 << 10;
pub const BPF_F_PRESERVE_ELEMS: u32  = 1 << 11;
pub const BPF_F_INNER_MAP: u32       = 1 << 12;
pub const BPF_F_LINK: u32            = 1 << 13;
pub const BPF_F_PATH_FD: u32         = 1 << 14;
pub const BPF_F_VTYPE_BTF_OBJ_FD: u32 = 1 << 15;
pub const BPF_F_TOKEN_FD: u32        = 1 << 16;
pub const BPF_F_SEGV_ON_FAULT: u32   = 1 << 17;
pub const BPF_F_NO_USER_CONV: u32    = 1 << 18;

// --- Map types (enum bpf_map_type from uapi/linux/bpf.h) ---
pub type bpf_map_type = u32;
pub const bpf_map_type_BPF_MAP_TYPE_UNSPEC: bpf_map_type              = 0;
pub const bpf_map_type_BPF_MAP_TYPE_HASH: bpf_map_type                = 1;
pub const bpf_map_type_BPF_MAP_TYPE_ARRAY: bpf_map_type               = 2;
pub const bpf_map_type_BPF_MAP_TYPE_PROG_ARRAY: bpf_map_type          = 3;
pub const bpf_map_type_BPF_MAP_TYPE_PERF_EVENT_ARRAY: bpf_map_type    = 4;
pub const bpf_map_type_BPF_MAP_TYPE_PERCPU_HASH: bpf_map_type         = 5;
pub const bpf_map_type_BPF_MAP_TYPE_PERCPU_ARRAY: bpf_map_type        = 6;
pub const bpf_map_type_BPF_MAP_TYPE_STACK_TRACE: bpf_map_type         = 7;
pub const bpf_map_type_BPF_MAP_TYPE_CGROUP_ARRAY: bpf_map_type        = 8;
pub const bpf_map_type_BPF_MAP_TYPE_LRU_HASH: bpf_map_type            = 9;
pub const bpf_map_type_BPF_MAP_TYPE_LRU_PERCPU_HASH: bpf_map_type     = 10;
pub const bpf_map_type_BPF_MAP_TYPE_LPM_TRIE: bpf_map_type            = 11;
pub const bpf_map_type_BPF_MAP_TYPE_ARRAY_OF_MAPS: bpf_map_type       = 12;
pub const bpf_map_type_BPF_MAP_TYPE_HASH_OF_MAPS: bpf_map_type        = 13;
pub const bpf_map_type_BPF_MAP_TYPE_DEVMAP: bpf_map_type              = 14;
pub const bpf_map_type_BPF_MAP_TYPE_SOCKMAP: bpf_map_type             = 15;
pub const bpf_map_type_BPF_MAP_TYPE_CPUMAP: bpf_map_type              = 16;
pub const bpf_map_type_BPF_MAP_TYPE_XSKMAP: bpf_map_type              = 17;
pub const bpf_map_type_BPF_MAP_TYPE_SOCKHASH: bpf_map_type            = 18;
pub const bpf_map_type_BPF_MAP_TYPE_CGROUP_STORAGE: bpf_map_type      = 19;
pub const bpf_map_type_BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: bpf_map_type = 20;
pub const bpf_map_type_BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: bpf_map_type = 21;
pub const bpf_map_type_BPF_MAP_TYPE_QUEUE: bpf_map_type               = 22;
pub const bpf_map_type_BPF_MAP_TYPE_STACK: bpf_map_type               = 23;
pub const bpf_map_type_BPF_MAP_TYPE_SK_STORAGE: bpf_map_type          = 24;

// --- cBPF sock_filter instruction (used by the cBPF→eBPF converter) ---
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct sock_filter {
    pub code: u16,
    pub jt:   u8,
    pub jf:   u8,
    pub k:    u32,
}
