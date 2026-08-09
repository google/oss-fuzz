/*
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};
use serde_urlencoded;
use std::collections::HashMap;
use std::fmt::Debug;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Arbitrary)]
enum PlainEnum {
    A,
    B,
    C,
    D,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Arbitrary)]
enum Enum {
    A(u8),
    B(()),
    C(Vec<PlainEnum>),
    D(i128),
    E { a: u8 },
    F(u8, u8),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Arbitrary)]
struct UnitStruct;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Arbitrary)]
struct BasicStruct {
    a: i8,
}

type PairKey = u64;

#[derive(Debug, Clone, PartialEq, Arbitrary, Serialize, Deserialize)]
struct Data {
    _bool: bool,
    _i8: i8,
    _i16: i16,
    _i32: i32,
    _i64: i64,
    _i128: i128,
    _u8: u8,
    _u16: u16,
    _u32: u32,
    _u64: u64,
    _u128: u128,
    _char: char,
    _string: String,
    _unit: (),
    _tuple: (u8, u16, String),
    _enum: Enum,
    _plain_enum: PlainEnum,
    _vec_enum: Vec<Enum>,
    _vec_plain_enum: Vec<PlainEnum>,
    _vec_bool: Vec<bool>,
    _vec_char: Vec<char>,
    _vec_u8: Vec<u8>,
    _vec_u16: Vec<u16>,
    _vec_u32: Vec<u32>,
    _vec_u64: Vec<u64>,
    _vec_i8: Vec<i8>,
    _vec_i16: Vec<i16>,
    _vec_i32: Vec<i32>,
    _vec_i64: Vec<i64>,
    _vec_f32: Vec<f32>,
    _vec_f64: Vec<f64>,
    _vec_pair: Vec<(String, String)>,
    _vec_pair_option: Vec<(PairKey, Option<()>)>,
    _vec_pair_vec_u8: Vec<(PairKey, Vec<u8>)>,
    _vec_pair_bool: Vec<(PairKey, bool)>,
    _vec_pair_char: Vec<(PairKey, u64)>,
    _vec_pair_i8: Vec<(PairKey, i8)>,
    _vec_pair_i16: Vec<(PairKey, i8)>,
    _vec_pair_i32: Vec<(PairKey, i8)>,
    _vec_pair_i64: Vec<(PairKey, i8)>,
    _vec_pair_u8: Vec<(PairKey, u8)>,
    _vec_pair_u16: Vec<(PairKey, u16)>,
    _vec_pair_u32: Vec<(PairKey, u32)>,
    _vec_pair_u64: Vec<(PairKey, u64)>,
    _vec_pair_f32: Vec<(PairKey, f32)>,
    _vec_pair_f64: Vec<(PairKey, f64)>,
    _vec_pair_variant: Vec<(PairKey, Enum)>,
    _vec_pair_basic_struct: Vec<(PairKey, BasicStruct)>,
    _vec_tuple: Vec<(String, String, String)>,
    _hashmap: HashMap<PairKey, String>,
}

fn round_trip<T>(val: T, check_equality: bool)
where
    T: PartialEq + Serialize + for<'a> Deserialize<'a> + Debug + Clone,
{
    use std::io::Cursor;
    match serde_urlencoded::to_string(&val) {
        Ok(encoded_url) => {
            let reader = Cursor::new(&encoded_url);
            _ = serde_urlencoded::from_reader::<T, std::io::Cursor<&std::string::String>>(reader);
            let decoded: T = serde_urlencoded::from_str::<T>(&encoded_url).unwrap();
            if check_equality {
                assert_eq!(decoded, val);
            }
        }
        Err(err) => {
            _ = format!("{err:#?}");
            _ = format!("{err:?}");
        }
    }
}

fuzz_target!(|data: Data| {
    round_trip(data._bool.clone(), true);
    round_trip(data._i8.clone(), true);
    round_trip(data._i16.clone(), true);
    round_trip(data._i32.clone(), true);
    round_trip(data._i64.clone(), true);
    round_trip(data._i128.clone(), true);
    round_trip(data._u8.clone(), true);
    round_trip(data._u16.clone(), true);
    round_trip(data._u32.clone(), true);
    round_trip(data._u64.clone(), true);
    round_trip(data._u128.clone(), true);
    round_trip(data._char.clone(), true);
    round_trip(data._string.clone(), true);
    round_trip(data._unit.clone(), true);
    round_trip(data._tuple.clone(), true);
    round_trip(data._enum.clone(), true);
    round_trip(data._plain_enum.clone(), true);
    round_trip(data._vec_enum.clone(), true);
    round_trip(data._vec_plain_enum.clone(), true);
    round_trip(data._vec_char.clone(), true);
    round_trip(data._vec_bool.clone(), true);
    round_trip(data._vec_u8.clone(), true);
    round_trip(data._vec_u16.clone(), true);
    round_trip(data._vec_u32.clone(), true);
    round_trip(data._vec_u64.clone(), true);
    round_trip(data._vec_i8.clone(), true);
    round_trip(data._vec_i16.clone(), true);
    round_trip(data._vec_i32.clone(), true);
    round_trip(data._vec_i64.clone(), true);
    round_trip(data._vec_f32.clone(), true);
    round_trip(data._vec_f64.clone(), true);
    round_trip(data._vec_pair.clone(), true);
    round_trip(data._vec_pair_option.clone(), false);
    round_trip(data._vec_pair_bool.clone(), true);
    round_trip(data._vec_pair_char.clone(), true);
    round_trip(data._vec_pair_i8.clone(), true);
    round_trip(data._vec_pair_i16.clone(), true);
    round_trip(data._vec_pair_i32.clone(), true);
    round_trip(data._vec_pair_i64.clone(), true);
    round_trip(data._vec_pair_u8.clone(), true);
    round_trip(data._vec_pair_u16.clone(), true);
    round_trip(data._vec_pair_u32.clone(), true);
    round_trip(data._vec_pair_u64.clone(), true);
    round_trip(data._vec_pair_variant.clone(), true);
    round_trip(data._vec_pair_vec_u8.clone(), true);
    round_trip(data._vec_tuple.clone(), true);
    round_trip(data._hashmap.clone(), true);
});
