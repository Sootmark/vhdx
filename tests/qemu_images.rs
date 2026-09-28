//! VHDX files made by `qemu-img convert -O vhdx -o block_size=1M` from known
//! raw disks: reading the virtual disk must give back the raw disk exactly.
//!
//! - `fin-wks-07-{dynamic,fixed}.vhdx`: the synthetic FIN-WKS-07 GPT disk
//!   (from `Sootmark/disk`), SHA-256 `67fb9a79…3ebe`.
//! - `sparse-dynamic.vhdx`: 8 MiB; first MiB from FIN-WKS-07, last MiB a
//!   byte pattern, zeros in between (unallocated blocks), SHA-256 `a527222e…1c1c`.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

use common::sha256::{hex, Sha256};
use disk::{partitions, NtfsVolume, Scheme};
use sootmark_vhdx::Vhdx;

const FIN_WKS_07_SHA256: &str = "67fb9a797f92d66d444a0bfcf3521f9060da3050fcfb6f37cbdc5af4dffe3ebe";
const FIN_WKS_07_SIZE: u64 = 1_802_240;
const SPARSE_SHA256: &str = "a527222eb2e4135155f2dd851403b8d741feb289235a020838d04e3cfa3a1c1c";
const MIB: usize = 1 << 20;

fn open(name: &str) -> Vhdx<BufReader<File>> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    Vhdx::open(BufReader::new(File::open(path).expect("fixture"))).expect("a valid VHDX")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn read_all(disk: &mut impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    disk.read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn dynamic_and_fixed_disks_read_back_the_raw_disk() {
    for name in ["fin-wks-07-dynamic.vhdx", "fin-wks-07-fixed.vhdx"] {
        let mut disk = open(name);
        assert_eq!(disk.virtual_size(), FIN_WKS_07_SIZE, "{name}");
        assert!(!disk.has_pending_log(), "{name}");
        assert_eq!(
            sha256_hex(&read_all(&mut disk)),
            FIN_WKS_07_SHA256,
            "{name}"
        );
    }
}

#[test]
fn unallocated_blocks_read_as_zeros() {
    let mut disk = open("sparse-dynamic.vhdx");
    let bytes = read_all(&mut disk);
    assert_eq!(bytes.len(), 8 * MIB);
    assert!(bytes[MIB..7 * MIB].iter().all(|&b| b == 0));
    assert_eq!(sha256_hex(&bytes), SPARSE_SHA256);
}

#[test]
fn reads_across_block_boundaries_and_after_seeking() {
    let mut disk = open("sparse-dynamic.vhdx");
    let whole = read_all(&mut disk);
    let start = 7 * MIB - 10;
    disk.seek(SeekFrom::Start(start as u64)).unwrap();
    let mut span = vec![0u8; 20];
    disk.read_exact(&mut span).unwrap();
    assert_eq!(span, whole[start..start + 20]);
    assert_eq!(disk.read(&mut [0u8; 4]).unwrap(), 4);
    disk.seek(SeekFrom::End(0)).unwrap();
    assert_eq!(disk.read(&mut [0u8; 4]).unwrap(), 0, "end of disk");
}

#[test]
fn partitions_and_ntfs_work_through_the_vhdx() {
    let mut disk = open("fin-wks-07-dynamic.vhdx");
    let size = disk.virtual_size();
    let (scheme, parts) = partitions(&mut disk, size).unwrap();
    assert_eq!(scheme, Scheme::Gpt);
    let volume = NtfsVolume::open(&mut disk, parts[1].offset, parts[1].length).unwrap();
    assert_eq!(volume.files(&mut disk).unwrap().len(), 17);
}

#[test]
fn rejects_non_vhdx_files() {
    let raw = std::io::Cursor::new(vec![0u8; 512 * 1024]);
    assert_eq!(
        Vhdx::open(raw).err().unwrap().kind(),
        std::io::ErrorKind::InvalidData
    );
}
