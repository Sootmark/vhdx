//! Hostile VHDX files: corrupted headers, region tables, metadata and BAT
//! entries yield errors, never panics.

use std::io::{Cursor, Read};

use proptest::prelude::*;
use sootmark_vhdx::Vhdx;

const FIXTURE: &[u8] = include_bytes!("fixtures/sparse-dynamic.vhdx");
/// Headers, region tables, and the start of the metadata and BAT regions:
/// where the structures live in qemu-made files (the first 5 MiB).
const STRUCTURES: std::ops::Range<usize> = 0..5 << 20;
/// Bytes read per case, as a consumer would budget.
const READ_BUDGET: u64 = 16 << 20;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn corrupted_structures_never_panic(flips in proptest::collection::vec((STRUCTURES, any::<u8>()), 1..32)) {
        let mut bytes = FIXTURE.to_vec();
        for (at, value) in flips {
            bytes[at] = value;
        }
        if let Ok(disk) = Vhdx::open(Cursor::new(bytes)) {
            let _ = disk.take(READ_BUDGET).read_to_end(&mut Vec::new());
        }
    }

    #[test]
    fn truncated_files_never_panic(len in 0usize..FIXTURE.len()) {
        if let Ok(disk) = Vhdx::open(Cursor::new(FIXTURE[..len].to_vec())) {
            let _ = disk.take(READ_BUDGET).read_to_end(&mut Vec::new());
        }
    }
}
