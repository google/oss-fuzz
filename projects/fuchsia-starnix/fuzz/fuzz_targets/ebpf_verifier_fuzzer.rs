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
//
// Fuzz target: Starnix eBPF verifier + executor
//
// Exercises the full verify → link → execute pipeline with arbitrary BPF
// instruction sequences. Targets:
//   - Off-by-one in StackOffset::is_valid() (verifier.rs): `value <=
//     BPF_STACK_SIZE` allows offset=512 (index 64) to pass verification.
//   - Missing STACK_MAX_INDEX guard in Stack::store() (verifier.rs): the
//     executor writes 8 bytes past the end of ComputationContext::stack,
//     corrupting ComputationContext::pc → OOB slice panic → abort.
//
// Crash seed (32 bytes, little-endian BPF encoding):
//   b7 01 00 00 02 00 00 00  -- mov64 r1, 2
//   7b 1a 00 00 00 00 00 00  -- stxdw [r10+0], r1  (passes verifier, OOB write)
//   b7 00 00 00 00 00 00 00  -- mov64 r0, 0
//   95 00 00 00 00 00 00 00  -- exit

#![no_main]

use ebpf::{
    BpfValue, CallingContext, EbpfInstruction, EbpfProgramContext, MapReference, MapSchema,
    NullVerifierLogger, empty_static_helper_set, link_program, verify_program,
};
use libfuzzer_sys::fuzz_target;
use zerocopy::FromBytes as _;

struct NoopMap;

impl MapReference for NoopMap {
    fn schema(&self) -> &MapSchema { unreachable!() }
    fn as_bpf_value(&self) -> BpfValue { unreachable!() }
    fn get_data_ptr(&self) -> Option<BpfValue> { unreachable!() }
}

struct FuzzContext;

impl EbpfProgramContext for FuzzContext {
    type RunContext<'a> = ();
    type Packet<'a>     = ();
    type Arg1<'a>       = ();
    type Arg2<'a>       = ();
    type Arg3<'a>       = ();
    type Arg4<'a>       = ();
    type Arg5<'a>       = ();
    type Map            = NoopMap;
}

empty_static_helper_set!(FuzzContext);

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() % 8 != 0 || data.len() > 8 * 4096 {
        return;
    }

    let Ok(insns) = <[EbpfInstruction]>::ref_from_bytes(data) else {
        return;
    };

    let calling_context = CallingContext {
        maps:        vec![],
        helpers:     Default::default(),
        args:        vec![],
        packet_type: None,
    };

    // Programs with memory-safety bugs PASS verification — that is the bug.
    let Ok(verified) = verify_program(insns.to_vec(), calling_context, &mut NullVerifierLogger)
    else {
        return;
    };

    let Ok(program) = link_program::<FuzzContext>(&verified, vec![]) else {
        return;
    };

    program.run_with_1_argument(&mut (), ());
});
