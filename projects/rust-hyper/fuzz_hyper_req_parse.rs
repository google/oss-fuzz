#[inline(always)]
pub fn fuzz_header_req_parse(data: &[u8]) -> Result<(), std::io::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);

    req.parse(data);
    Ok(())
}
