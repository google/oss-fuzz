#![no_main]
extern crate libfuzzer_sys;
use libfuzzer_sys::fuzz_target;
extern crate png;

use std::io::{BufRead, Read, Result};

/// A reader that reads at most `n` bytes.
struct SmalBuf<R: BufRead> {
    inner: R,
    cap: usize,
}

impl<R: BufRead> SmalBuf<R> {
    fn new(inner: R, cap: usize) -> Self {
        SmalBuf { inner, cap }
    }
}

impl<R: BufRead> Read for SmalBuf<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let len = buf.len().min(self.cap);
        self.inner.read(&mut buf[..len])
    }
}

impl<R: BufRead> BufRead for SmalBuf<R> {
    fn fill_buf(&mut self) -> Result<&[u8]> {
        let buf = self.inner.fill_buf()?;
        let len = buf.len().min(self.cap);
        Ok(&buf[..len])
    }

    fn consume(&mut self, amt: usize) {
        assert!(amt <= self.cap);
        self.inner.consume(amt)
    }
}

fuzz_target!(|data: &[u8]| {
    // Small limits, we don't need them hopefully.
    let limits = png::Limits { bytes: 1 << 16 };

    let reference = png::Decoder::new_with_limits(data, limits);
    let smal = png::Decoder::new_with_limits(SmalBuf::new(data, 1), limits);

    let _ = png_compare(reference, smal);
});

#[inline(always)]
fn png_compare<R: BufRead, S: BufRead>(reference: png::Decoder<R>, smal: png::Decoder<S>)
    -> std::result::Result<png::OutputInfo, ()>
{
    let mut smal = Some(smal);
    let (info, mut reference) = reference.read_info().map_err(|_| {
        assert!(smal.take().unwrap().read_info().is_err());
    })?;

    let (sinfo, mut smal) = smal.take().unwrap().read_info().expect("Deviation");
    assert_eq!(info, sinfo);

    if info.buffer_size() > 5_000_000 {
        return Err(());
    }

    let mut ref_data = vec![0; info.buffer_size()];
    let mut smal_data = vec![0; info.buffer_size()];

    let _rref = reference.next_frame(&mut ref_data);
    let _rsmal = smal.next_frame(&mut smal_data);

    assert_eq!(smal_data, ref_data);
    return Ok(info);
}
