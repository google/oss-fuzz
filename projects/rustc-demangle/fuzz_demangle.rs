use std::fmt::*;

#[inline(always)]
pub fn fuzz_demangle(data: &[u8]) -> Result {
    if let Ok(sd) = std::str::from_utf8(data) {
        let mut s = String::new();
        let sym = rustc_demangle::demangle(sd);
        drop(write!(s, "{}", sym));
        s.truncate(0);

        if let Ok(sym) = rustc_demangle::try_demangle(sd) {
            drop(write!(s, "{}", sym));
        }
    }
    Ok(())
}
