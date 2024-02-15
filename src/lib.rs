#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]
#![cfg_attr(bench, feature(test))]
#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(bench)]
extern crate test;

pub mod bsl;
mod error;
pub mod number;
mod parse_result;
mod slice;
mod visit;

#[cfg(feature = "slice_cache")]
mod slice_cache;

#[cfg(feature = "slice_cache")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "slice_cache")]
pub use slice_cache::SliceCache;

pub use error::Error;
pub use parse_result::ParseResult;
pub use slice::read_slice;
pub use visit::{EmptyVisitor, Parse, Visit, Visitor};

/// Common result type throughout the lib
pub type SResult<'a, T> = Result<ParseResult<'a, T>, Error>;

#[cfg(feature = "groestlcoin_hashes")]
pub use groestlcoin_hashes;

#[cfg(feature = "sha2")]
pub use sha2;

#[cfg(feature = "redb")]
pub use redb;

#[cfg(feature = "groestlcoin")]
pub use groestlcoin;

#[cfg(any(test, bench))]
pub mod test_common {
    use hex_lit::hex;

    use crate::ParseResult;

    pub const GENESIS_TX: [u8; 185] = hex!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3a04ffff001d0104325072657373757265206d75737420626520707574206f6e20566c6164696d697220507574696e206f766572204372696d6561ffffffff010000000000000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
    pub const GENESIS_BLOCK_HEADER: [u8; 80] = hex!("700000000000000000000000000000000000000000000000000000000000000000000000bb2866aaca46c4428ad08b57bc9d1493abaf64724b6c3052a7c8f958df68e93ced3d2b53ffff0f1e835b0300");
    pub const GENESIS_BLOCK: [u8;266] = hex!("700000000000000000000000000000000000000000000000000000000000000000000000bb2866aaca46c4428ad08b57bc9d1493abaf64724b6c3052a7c8f958df68e93ced3d2b53ffff0f1e835b03000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3a04ffff001d0104325072657373757265206d75737420626520707574206f6e20566c6164696d697220507574696e206f766572204372696d6561ffffffff010000000000000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");

    impl<'a, T: AsRef<[u8]>> ParseResult<'a, T> {
        pub fn new_exact(parsed: T) -> Self {
            ParseResult::new(&[], parsed)
        }
    }

    pub fn reverse(arr: [u8; 32]) -> [u8; 32] {
        let mut ret = arr;
        ret.reverse();
        ret
    }
}

/// Common functions used in fuzzing
#[cfg(fuzzing)]
pub mod fuzzing {
    use crate::{Error, ParseResult};

    /// Some checks on a succesfull parse
    pub fn check<T: AsRef<[u8]>>(data: &[u8], p: Result<ParseResult<T>, Error>) {
        if let Ok(p) = p {
            let consumed = p.consumed();
            assert_eq!(p.parsed().as_ref().len(), consumed);
            assert_eq!(&data[..consumed], p.parsed().as_ref());
            assert_eq!(&data[consumed..], p.remaining());
        }
    }
}
