#[inline(always)]
pub fn fuzz_header_name_parse(data: &[u8]) -> Result<(), std::io::Error> {
    hyper::header::HeaderName::from_bytes(data);
    Ok(())
}
