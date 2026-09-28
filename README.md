# vhdx

Read-only VHDX virtual disks (the container KAPE writes with `--vhdx`), exposed as a `Read + Seek` stream so partition and file-system readers use them like raw images. Written from the specification (MS-VHDX); the only runtime dependency is [`Sootmark/common`](https://github.com/Sootmark/common).

```rust
let mut disk = vhdx::Vhdx::open(std::io::BufReader::new(std::fs::File::open("WS-042.vhdx")?))?;
if disk.has_pending_log() {
    eprintln!("warning: the VHDX was not closed cleanly; reading blocks as they are on disk");
}
let size = disk.virtual_size();
let (_, partitions) = disk::partitions(&mut disk, size)?;
```

- Dynamic and fixed disks; differencing disks (which need their parent) are rejected with a clear error.
- Headers and region tables validated with CRC-32C; the valid header with the highest sequence number wins; the backup region table is used if the primary is damaged.
- Unallocated, zero and unmapped blocks read as zeros.
- **Pending log**: an uncleanly closed VHDX may hold writes in its log that haven't reached the blocks. The log is not replayed; `has_pending_log()` reports it so intake can flag the evidence.

## Verification

Fixtures are made with `qemu-img convert -O vhdx -o block_size=1M` from known raw disks (the synthetic FIN-WKS-07 GPT disk from [`Sootmark/disk`](https://github.com/Sootmark/disk), and an 8 MiB sparse disk):

| Check | Result |
|---|---|
| Dynamic and fixed VHDX → virtual disk | byte-identical to the raw disk (SHA-256) |
| Unallocated blocks | read as zeros |
| Reads across block boundaries, seeks | correct |
| Partitions and NTFS listing through the VHDX | same as on the raw disk |
| Corrupted headers, region tables, metadata, BAT; truncated files | errors, never panics |

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
