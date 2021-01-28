#![no_main]
#![feature(rustc_private)]
use libfuzzer_sys::fuzz_target;

use std::convert::TryFrom;

use compiler_builtins::float::add::__addsf3;
use compiler_builtins::float::sub::__subsf3;
use compiler_builtins::float::Float;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let x = f32::from_ne_bytes(<[u8; 4]>::try_from(&data[0..4]).unwrap());
    let y = f32::from_ne_bytes(<[u8; 4]>::try_from(&data[4..8]).unwrap());

    let add0 = x + y;
    let add1: f32 = __addsf3(x, y);
    if !Float::eq_repr(add0, add1) {
        panic!(
            "{}({}, {}): std: {}, builtins: {}",
            stringify!($fn_add), x, y, add0, add1
        );
    }

    let sub0 = x - y;
    let sub1: f32 = __subsf3(x, y);
    if !Float::eq_repr(sub0, sub1) {
        panic!(
            "{}({}, {}): std: {}, builtins: {}",
            stringify!($fn_sub), x, y, sub0, sub1
        );
    }
});
