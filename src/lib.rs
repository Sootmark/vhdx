//! Read-only VHDX virtual disks.
//!
//! [`Vhdx`] exposes the virtual disk inside a `.vhdx` file as a `Read + Seek`
//! stream, so partition and file-system readers can use it like a raw image.
//! Dynamic and fixed disks are supported; differencing disks (which need a
//! parent) are rejected. Headers and region tables are checksum-validated.
//!
//! **Pending log.** A VHDX that wasn't closed cleanly can hold writes in its
//! log that haven't reached the blocks yet. This reader doesn't replay the
//! log: it reports the condition with [`Vhdx::has_pending_log`] so intake can
//! flag the evidence, and reads the blocks as they are on disk.

mod crc32c;

use std::io::{self, Read, Seek, SeekFrom};

use common::bytes::Reader;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const FILE_SIGNATURE: &[u8; 8] = b"vhdxfile";
const HEADER_OFFSETS: [u64; 2] = [64 * KIB, 128 * KIB];
const HEADER_SIZE: usize = 4 * KIB as usize;
const HEADER_SIGNATURE: &[u8; 4] = b"head";
const REGION_TABLE_OFFSETS: [u64; 2] = [192 * KIB, 256 * KIB];
const REGION_TABLE_SIZE: usize = 64 * KIB as usize;
const REGION_TABLE_SIGNATURE: &[u8; 4] = b"regi";
const METADATA_SIGNATURE: &[u8; 8] = b"metadata";
/// Every checksummed structure stores its CRC-32C at offset 4.
const CHECKSUM_OFFSET: usize = 4;
const SUPPORTED_VERSION: u16 = 1;
const MAX_REGION_ENTRIES: u32 = 2047;
const MAX_METADATA_ENTRIES: u16 = 2047;
const MAX_METADATA_REGION: u32 = 16 * MIB as u32;
const MAX_VIRTUAL_SIZE: u64 = 64 * 1024 * 1024 * MIB; // 64 TiB
const MIN_BLOCK_SIZE: u32 = MIB as u32;
const MAX_BLOCK_SIZE: u32 = 256 * MIB as u32;
/// Sectors covered by one sector-bitmap block: 2^23.
const SECTORS_PER_BITMAP_BLOCK: u64 = 1 << 23;

/// Payload block states in the BAT (the low 3 bits of an entry).
mod block_state {
    pub const NOT_PRESENT: u64 = 0;
    pub const UNDEFINED: u64 = 1;
    pub const ZERO: u64 = 2;
    pub const UNMAPPED: u64 = 3;
    pub const FULLY_PRESENT: u64 = 6;
}
const BLOCK_STATE_MASK: u64 = 0b111;
/// BAT entries store the block's file offset in MiB from bit 20.
const FILE_OFFSET_SHIFT: u32 = 20;

/// Region and metadata item identifiers, in their on-disk byte order.
mod ids {
    pub const BAT: [u8; 16] = super::guid(
        0x2dc2_7766,
        0xf623,
        0x4200,
        [0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08],
    );
    pub const METADATA: [u8; 16] = super::guid(
        0x8b7c_a206,
        0x4790,
        0x4b9a,
        [0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e],
    );
    pub const FILE_PARAMETERS: [u8; 16] = super::guid(
        0xcaa1_6737,
        0xfa36,
        0x4d43,
        [0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b],
    );
    pub const VIRTUAL_DISK_SIZE: [u8; 16] = super::guid(
        0x2fa5_4224,
        0xcd1b,
        0x4876,
        [0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8],
    );
    pub const LOGICAL_SECTOR_SIZE: [u8; 16] = super::guid(
        0x8141_bf1d,
        0xa96f,
        0x4709,
        [0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f],
    );
}

/// A GUID in the mixed-endian layout Windows stores on disk.
const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

/// A VHDX virtual disk, readable as a raw disk.
pub struct Vhdx<R> {
    inner: R,
    geometry: Geometry,
    bat: Vec<u64>,
    has_pending_log: bool,
    position: u64,
}

#[derive(Debug, Clone, Copy)]
struct Geometry {
    virtual_size: u64,
    block_size: u64,
    /// Payload blocks between two sector-bitmap entries in the BAT.
    chunk_ratio: u64,
}

impl<R: Read + Seek> Vhdx<R> {
    /// Open the VHDX file read by `inner`.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidData`] when the file isn't a readable VHDX
    /// (bad signatures or checksums, unsupported version, differencing disk,
    /// impossible geometry), or on read errors.
    pub fn open(mut inner: R) -> io::Result<Self> {
        if read_at(&mut inner, 0, FILE_SIGNATURE.len())? != FILE_SIGNATURE {
            return Err(invalid("not a VHDX file (bad file signature)"));
        }
        let header = current_header(&mut inner)?;
        let regions = region_table(&mut inner)?;
        let (bat_region, metadata_region) =
            (find(&regions, ids::BAT)?, find(&regions, ids::METADATA)?);
        let geometry = geometry(&read_metadata(&mut inner, metadata_region)?)?;
        let bat = read_bat(&mut inner, bat_region, &geometry)?;
        Ok(Self {
            inner,
            geometry,
            bat,
            has_pending_log: header.has_pending_log,
            position: 0,
        })
    }

    /// Size of the virtual disk in bytes.
    #[must_use]
    pub const fn virtual_size(&self) -> u64 {
        self.geometry.virtual_size
    }

    /// Whether the log holds writes not yet applied to the blocks (the file
    /// wasn't closed cleanly). Reads return the blocks as they are on disk.
    #[must_use]
    pub const fn has_pending_log(&self) -> bool {
        self.has_pending_log
    }

    /// Read from the block holding `self.position`, up to the end of that block.
    fn read_in_block(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Geometry {
            virtual_size,
            block_size,
            chunk_ratio,
        } = self.geometry;
        let block = self.position / block_size;
        let within = self.position % block_size;
        let available = (block_size - within).min(virtual_size - self.position);
        let wanted = buf
            .len()
            .min(usize::try_from(available).unwrap_or(usize::MAX));
        let buf = &mut buf[..wanted];
        let entry = self.bat[usize::try_from(block + block / chunk_ratio)
            .map_err(|_| invalid("block index overflow"))?];
        match entry & BLOCK_STATE_MASK {
            block_state::FULLY_PRESENT => {
                let file_offset = (entry >> FILE_OFFSET_SHIFT) * MIB + within;
                self.inner.seek(SeekFrom::Start(file_offset))?;
                self.inner.read_exact(buf)?;
            }
            block_state::NOT_PRESENT
            | block_state::UNDEFINED
            | block_state::ZERO
            | block_state::UNMAPPED => buf.fill(0),
            _ => return Err(invalid("unsupported block state (differencing disk?)")),
        }
        Ok(wanted)
    }
}

impl<R: Read + Seek> Read for Vhdx<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.geometry.virtual_size {
            return Ok(0);
        }
        let read = self.read_in_block(buf)?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<R> Seek for Vhdx<R> {
    fn seek(&mut self, target: SeekFrom) -> io::Result<u64> {
        let position = match target {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.geometry.virtual_size.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        self.position = position.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek before start of disk")
        })?;
        Ok(self.position)
    }
}

struct Header {
    sequence: u64,
    has_pending_log: bool,
}

/// The valid header with the highest sequence number.
fn current_header<R: Read + Seek>(inner: &mut R) -> io::Result<Header> {
    let mut valid = Vec::with_capacity(HEADER_OFFSETS.len());
    for offset in HEADER_OFFSETS {
        valid.extend(parse_header(&read_at(inner, offset, HEADER_SIZE)?));
    }
    valid
        .into_iter()
        .max_by_key(|header| header.sequence)
        .ok_or_else(|| invalid("no valid VHDX header"))
}

fn parse_header(bytes: &[u8]) -> Option<Header> {
    if bytes.len() < HEADER_SIZE || &bytes[..4] != HEADER_SIGNATURE || !checksum_ok(bytes) {
        return None;
    }
    let mut r = Reader::new(bytes);
    r.seek(8).ok()?;
    let sequence = r.u64_le().ok()?;
    r.skip(32).ok()?; // file write and data write GUIDs
    let log_guid = r.array::<16>().ok()?;
    r.skip(2).ok()?; // log version
    let version = r.u16_le().ok()?;
    (version == SUPPORTED_VERSION).then_some(Header {
        sequence,
        has_pending_log: log_guid != [0; 16],
    })
}

#[derive(Debug, Clone, Copy)]
struct Region {
    id: [u8; 16],
    offset: u64,
    length: u32,
}

/// The first region table (primary, then backup) whose checksum is valid.
fn region_table<R: Read + Seek>(inner: &mut R) -> io::Result<Vec<Region>> {
    for offset in REGION_TABLE_OFFSETS {
        let bytes = read_at(inner, offset, REGION_TABLE_SIZE)?;
        if bytes.len() == REGION_TABLE_SIZE
            && &bytes[..4] == REGION_TABLE_SIGNATURE
            && checksum_ok(&bytes)
        {
            return parse_regions(&bytes);
        }
    }
    Err(invalid("no valid VHDX region table"))
}

fn parse_regions(bytes: &[u8]) -> io::Result<Vec<Region>> {
    let mut r = Reader::new(bytes);
    r.seek(8).map_err(read_error)?;
    let count = r.u32_le().map_err(read_error)?;
    if count > MAX_REGION_ENTRIES {
        return Err(invalid("too many region table entries"));
    }
    r.skip(4).map_err(read_error)?;
    (0..count)
        .map(|_| {
            let id = r.array::<16>().map_err(read_error)?;
            let offset = r.u64_le().map_err(read_error)?;
            let length = r.u32_le().map_err(read_error)?;
            let required = r.u32_le().map_err(read_error)? & 1 == 1;
            let known = id == ids::BAT || id == ids::METADATA;
            if required && !known {
                return Err(invalid("unknown required region"));
            }
            Ok(Region { id, offset, length })
        })
        .collect()
}

fn find(regions: &[Region], id: [u8; 16]) -> io::Result<Region> {
    regions
        .iter()
        .copied()
        .find(|r| r.id == id)
        .ok_or_else(|| invalid("missing required region"))
}

/// Metadata items by id: `(id, value bytes)`.
fn read_metadata<R: Read + Seek>(
    inner: &mut R,
    region: Region,
) -> io::Result<Vec<([u8; 16], Vec<u8>)>> {
    if region.length > MAX_METADATA_REGION {
        return Err(invalid("metadata region too large"));
    }
    let bytes = read_at(inner, region.offset, region.length as usize)?;
    let mut r = Reader::new(&bytes);
    if r.array::<8>().map_err(read_error)? != *METADATA_SIGNATURE {
        return Err(invalid("bad metadata signature"));
    }
    r.skip(2).map_err(read_error)?;
    let count = r.u16_le().map_err(read_error)?;
    if count > MAX_METADATA_ENTRIES {
        return Err(invalid("too many metadata entries"));
    }
    r.skip(20).map_err(read_error)?;
    let mut items = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let id = r.array::<16>().map_err(read_error)?;
        let offset = r.u32_le().map_err(read_error)? as usize;
        let length = r.u32_le().map_err(read_error)? as usize;
        r.skip(8).map_err(read_error)?; // flags, reserved
        let value = offset
            .checked_add(length)
            .and_then(|end| bytes.get(offset..end))
            .ok_or_else(|| invalid("metadata item outside its region"))?;
        items.push((id, value.to_vec()));
    }
    Ok(items)
}

fn geometry(items: &[([u8; 16], Vec<u8>)]) -> io::Result<Geometry> {
    let item = |id| {
        items
            .iter()
            .find(|(item, _)| *item == id)
            .map(|(_, v)| v.as_slice())
            .ok_or_else(|| invalid("missing metadata item"))
    };
    let mut parameters = Reader::new(item(ids::FILE_PARAMETERS)?);
    let block_size = parameters.u32_le().map_err(read_error)?;
    let has_parent = parameters.u32_le().map_err(read_error)? & 0b10 != 0;
    let virtual_size = Reader::new(item(ids::VIRTUAL_DISK_SIZE)?)
        .u64_le()
        .map_err(read_error)?;
    let sector_size = Reader::new(item(ids::LOGICAL_SECTOR_SIZE)?)
        .u32_le()
        .map_err(read_error)?;
    if has_parent {
        return Err(invalid(
            "differencing VHDX (needs its parent disk): not supported",
        ));
    }
    let block_size_ok =
        block_size.is_power_of_two() && (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size);
    let sector_size_ok = sector_size == 512 || sector_size == 4096;
    if !block_size_ok
        || !sector_size_ok
        || virtual_size > MAX_VIRTUAL_SIZE
        || virtual_size % u64::from(sector_size) != 0
    {
        return Err(invalid("impossible VHDX geometry"));
    }
    let chunk_ratio = SECTORS_PER_BITMAP_BLOCK * u64::from(sector_size) / u64::from(block_size);
    Ok(Geometry {
        virtual_size,
        block_size: u64::from(block_size),
        chunk_ratio,
    })
}

fn read_bat<R: Read + Seek>(
    inner: &mut R,
    region: Region,
    geometry: &Geometry,
) -> io::Result<Vec<u64>> {
    let payload_blocks = geometry.virtual_size.div_ceil(geometry.block_size);
    let entries = payload_blocks + payload_blocks.saturating_sub(1) / geometry.chunk_ratio;
    let bytes = entries
        .checked_mul(8)
        .filter(|&n| n <= u64::from(region.length))
        .ok_or_else(|| invalid("BAT region too small"))?;
    let raw = read_at(inner, region.offset, bytes as usize)?;
    if raw.len() as u64 != bytes {
        return Err(invalid("BAT truncated"));
    }
    Ok(raw
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
        .collect())
}

fn checksum_ok(bytes: &[u8]) -> bool {
    let stored = u32::from_le_bytes(
        bytes[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4]
            .try_into()
            .expect("4 bytes"),
    );
    crc32c::checksum_with_hole(bytes, CHECKSUM_OFFSET) == stored
}

fn read_at<R: Read + Seek>(inner: &mut R, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    inner.seek(SeekFrom::Start(offset))?;
    let mut buffer = Vec::with_capacity(len);
    inner.take(len as u64).read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[allow(clippy::needless_pass_by_value)] // used as a `map_err` adapter
fn read_error(error: common::bytes::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
