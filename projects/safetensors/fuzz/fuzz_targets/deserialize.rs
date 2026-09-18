#![no_main]
//! Fuzz the untrusted-input entry point of safetensors.
//!
//! `SafeTensors::deserialize` parses an 8-byte little-endian header length, a
//! JSON metadata header of that length, and per-tensor (dtype, shape,
//! [begin,end)) offset descriptors, then hands out `TensorView`s that index
//! back into the caller's buffer. The header-length / offset / shape math
//! against the backing buffer is the classic out-of-bounds seam in
//! memory-format deserializers.

use libfuzzer_sys::fuzz_target;
use safetensors::SafeTensors;

fuzz_target!(|data: &[u8]| {
    if let Ok(st) = SafeTensors::deserialize(data) {
        for (name, view) in st.tensors() {
            let _ = name.len();
            let _ = view.dtype();
            let _ = view.shape().to_vec();
            let _ = view.data().len();
        }
        for name in st.names() {
            let _ = st.tensor(name);
        }
    }
});
