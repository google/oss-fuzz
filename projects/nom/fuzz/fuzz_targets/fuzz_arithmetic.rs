#![no_main]
use libfuzzer_sys::fuzz_target;
use std::str;

extern crate nom;

use nom::{
  branch::alt,
  bytes::complete::tag,
  character::complete::char,
  character::complete::{digit1 as digit, space0 as space},
  combinator::map_res,
  multi::fold_many0,
  sequence::{delimited, pair},
  IResult,
};

use std::str::FromStr;

fn parens(i: &str) -> IResult<&str, i64> {
      delimited(space, delimited(tag("("), expr, tag(")")), space)(i)
}


fn factor(i: &str) -> IResult<&str, i64> {
  alt((
    map_res(delimited(space, digit, space), FromStr::from_str),
    parens,
  ))(i)
}


fn term(i: &str) -> IResult<&str, i64> {
  let (i, init) = factor(i)?;

  fold_many0(
    pair(alt((char('*'), char('/'))), factor),
    init,
    |acc, (op, val): (char, i64)| {
      if op == '*' {
        acc * val
      } else {
        acc / val
      }
    },
  )(i)
}

fn expr(i: &str) -> IResult<&str, i64> {
  let (i, init) = term(i)?;

  fold_many0(
    pair(alt((char('+'), char('-'))), term),
    init,
    |acc, (op, val): (char, i64)| {
      if op == '+' {
        acc + val
      } else {
        acc - val
      }
    },
  )(i)
}

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let temp = match str::from_utf8(data) {
        Ok(v) => factor(v),
        Err(e) => factor("2"),
    };
});
