/*
# Copyright 2022 Google LLC
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
use libfuzzer_sys::fuzz_target;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum PlainEnum {
    A,
    B,
    C,
    D,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum Enum {
    A(u8),
    B(()),
    C(Vec<PlainEnum>),
    D(i128),
    E { x: i8, y: String },
    F(u8, u8),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum FloatEnum {
    A(Enum),
    E(Option<f32>),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct TupleStruct(i32, String, i64);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Struct {
    _a: (),
    _b: u8,
    _c: Vec<Enum>,
    _d: (u128, i8, (), PlainEnum, String),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct FloatStruct {
    _a: Struct,
    _b: f64,
}

macro_rules! round_trip {
    ($ty:ty, $data:ident, $equality:expr) => {{
        #[cfg(feature = "debug")]
        println!("roundtripping {}", stringify!($ty));

        match ::serde_urlencoded::from_bytes::<$ty>($data) {
            Ok(inner) => {
                #[cfg(feature = "debug")]
                dbg!(&inner);

                let ser = ::serde_urlencoded::to_string(&inner)
                    .expect("a deserialized type should serialize");
                #[cfg(feature = "debug")]
                dbg!(&ser);

                let des: $ty = ::serde_urlencoded::from_bytes(ser.as_bytes())
                    .expect("a serialized type should deserialize");
                #[cfg(feature = "debug")]
                dbg!(&des);

                if $equality {
                    assert_eq!(inner, des, "roundtripped object changed");
                }
            }
            Err(e) => {
                _ = format!("{e:?}");
                _ = format!("{e:#?}");
            }
        }
    }};
}

macro_rules! from_bytes {
    ($ty:ty, $data_iter:ident, $equality:expr) => {{
        let data = $data_iter.next().unwrap_or(&[]);
        round_trip!($ty, data, $equality);
        let data = $data_iter.next().unwrap_or(&[]);
        round_trip!(Vec<$ty>, data, $equality);
        let data = $data_iter.next().unwrap_or(&[]);
        round_trip!(Option<$ty>, data, $equality);
        let data = $data_iter.next().unwrap_or(&[]);
        round_trip!(std::collections::HashMap<i32,$ty>, data, $equality);
    }};
}

fuzz_target!(|data: Vec<&[u8]>| {
    let mut data_iter = data.iter().copied();
    from_bytes!(bool, data_iter, true);
    from_bytes!(i8, data_iter, true);
    from_bytes!(i16, data_iter, true);
    from_bytes!(i32, data_iter, true);
    from_bytes!(i64, data_iter, true);
    from_bytes!(i128, data_iter, true);
    from_bytes!(u8, data_iter, true);
    from_bytes!(u16, data_iter, true);
    from_bytes!(u32, data_iter, true);
    from_bytes!(u64, data_iter, true);
    from_bytes!(u128, data_iter, true);
    from_bytes!(f32, data_iter, false);
    from_bytes!(f64, data_iter, false);
    from_bytes!(char, data_iter, true);
    from_bytes!(&str, data_iter, true);
    from_bytes!((String, i8), data_iter, true);
    from_bytes!((String, String), data_iter, true);
    from_bytes!((String, Option<String>), data_iter, false);
    from_bytes!((String, Option<i32>), data_iter, false);
    from_bytes!(TupleStruct, data_iter, true);
    from_bytes!((), data_iter, true);
    from_bytes!(PlainEnum, data_iter, true);
    from_bytes!(Enum, data_iter, true);
    from_bytes!(FloatEnum, data_iter, false);
    from_bytes!(Struct, data_iter, true);
    from_bytes!(FloatStruct, data_iter, false);
});
