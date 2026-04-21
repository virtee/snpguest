// SPDX-License-Identifier: Apache-2.0

//! Custom integer parsers for CLI arguments supporting multiple radix formats.
//!
//! Provides a clap-compatible value parser that accepts integers in:
//! - Decimal (e.g., `63`)
//! - Hexadecimal with `0x` prefix (e.g., `0x3f`)
//! - Binary with `0b` prefix (e.g., `0b111111`)

use std::num::ParseIntError;

/// Parse an integer string with automatic radix detection.
///
/// Supported formats:
/// - `0x...` — hexadecimal
/// - `0b...` — binary
/// - anything else — decimal
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

/// Trait for parsing integers from a string with a given radix.
///
/// Implemented for [`u32`] and [`u64`].
pub trait FromStrRadix: Sized {
    /// Parse `src` as an integer in the given `radix` (2, 10, or 16).
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
