// SPDX-License-Identifier: Apache-2.0
// This file contains custom u32/u64 parsers for supporting decimal, hexadecimal and binary formats.

use std::num::ParseIntError;

pub fn parse_int_auto_radix<T>(s: &str) -> Result<T, ParseIntError>
where
    T: FromStrRadix,
{
    if let Some(hex) = s.strip_prefix("0x") {
        T::from_str_radix(hex, 16)
    } else if let Some(bin) = s.strip_prefix("0b") {
        T::from_str_radix(bin, 2)
    } else {
        T::from_str_radix(s, 10)
    }
}

pub trait FromStrRadix: Sized {
    fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError>;
}

impl FromStrRadix for u32 {
    fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError> {
        u32::from_str_radix(src, radix)
    }
}

impl FromStrRadix for u64 {
    fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError> {
        u64::from_str_radix(src, radix)
    }
}
