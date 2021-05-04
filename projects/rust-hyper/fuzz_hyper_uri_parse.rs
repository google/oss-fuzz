
#[inline(always)]
pub fn fuzz_uri_parse(data: &[u8]) -> Result<(), std::io::Error> {
    if let Ok(sd) = std::str::from_utf8(data) {
        sd.parse::<hyper::Uri>();
    }
    Ok(())
}
