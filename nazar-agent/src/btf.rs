use std::fs;

use anyhow::{Result, anyhow, bail};

const BTF_MAGIC: u16 = 0xeB9F;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;

struct TypeEntry {
    name_off: u32,
    kind: u32,
    vlen: u32,
    kind_flag: bool,
    extra_off: usize,
}

fn extra_len(kind: u32, vlen: u32) -> Result<usize> {
    let n = vlen as usize;
    Ok(match kind {
        1 => 4,
        2 => 0,
        3 => 12,
        4 | 5 => n * 12,
        6 => n * 8,
        7..=12 => 0,
        13 => n * 8,
        14 => 4,
        15 => n * 12,
        16 => 0,
        17 => 4,
        18 => 0,
        19 => n * 12,
        other => bail!("unknown BTF kind {other}"),
    })
}

#[derive(Debug)]
struct BtfHeader {
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
    hdr_len: u32,
}

fn read_u16(buf: &[u8], off: usize) -> Result<u16> {
    let bytes = buf
        .get(off..off + 2)
        .ok_or_else(|| anyhow!("truncated at {off}"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], off: usize) -> Result<u32> {
    let bytes = buf
        .get(off..off + 4)
        .ok_or_else(|| anyhow!("truncated at {off}"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn parse_header(buf: &[u8]) -> Result<BtfHeader> {
    let magic = read_u16(buf, 0)?;
    if magic != BTF_MAGIC {
        bail!("bad BTF magic: 0x{magic:04x}");
    }
    let version = buf.get(2).copied().ok_or_else(|| anyhow!("truncated"))?;
    if version != 1 {
        bail!("unsupported BTF version {version}");
    }
    Ok(BtfHeader {
        hdr_len: read_u32(buf, 4)?,
        type_off: read_u32(buf, 8)?,
        type_len: read_u32(buf, 12)?,
        str_off: read_u32(buf, 16)?,
        str_len: read_u32(buf, 20)?,
    })
}

pub struct Btf {
    data: Vec<u8>,
    hdr: BtfHeader,
}

impl Btf {
    pub fn field_offset(&self, struct_name: &str, field: &str) -> Result<u32> {
        let found = self.walk_types(|entry| {
            if entry.kind != BTF_KIND_STRUCT && entry.kind != BTF_KIND_UNION {
                return Ok(None);
            }
            if self.name_at(entry.name_off)? != struct_name {
                return Ok(None);
            }
            for i in 0..entry.vlen as usize {
                let m = entry.extra_off + i * 12;
                let m_name = read_u32(&self.data, m)?;
                if self.name_at(m_name)? != field {
                    continue;
                }
                let raw = read_u32(&self.data, m + 8)?;
                let bit_off = if entry.kind_flag {
                    raw & 0x00ff_ffff
                } else {
                    raw
                };
                if bit_off % 8 != 0 {
                    bail!("{struct_name}.{field} is a bitfield (bit offset {bit_off})");
                }
                return Ok(Some(bit_off / 8));
            }
            bail!("{struct_name} has no field {field}");
        })?;
        found.ok_or_else(|| anyhow!("struct {struct_name} not found in BTF"))
    }
    fn walk_types<T>(
        &self,
        mut f: impl FnMut(&TypeEntry) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        let mut off = self.types_start();
        let end = self.types_end();

        while off < end {
            let name_off = read_u32(&self.data, off)?;
            let info = read_u32(&self.data, off + 4)?;

            let vlen = info & 0xffff;
            let kind = (info >> 24) & 0x1f;
            let kind_flag = (info >> 31) & 1 == 1;

            let entry = TypeEntry {
                name_off,
                kind,
                vlen,
                kind_flag,
                extra_off: off + 12,
            };

            if let Some(found) = f(&entry)? {
                return Ok(Some(found));
            }

            off = entry.extra_off + extra_len(kind, vlen)?;
        }
        Ok(None)
    }
    pub fn from_sys_fs() -> Result<Self> {
        let data = fs::read("/sys/kernel/btf/vmlinux")?;
        let hdr = parse_header(&data)?;
        Ok(Btf { data, hdr })
    }
    fn types_start(&self) -> usize {
        self.hdr.hdr_len as usize + self.hdr.type_off as usize
    }
    fn types_end(&self) -> usize {
        self.types_start() + self.hdr.type_len as usize
    }
    fn name_at(&self, name_off: u32) -> Result<&str> {
        if name_off == 0 {
            return Ok("");
        }
        let base = self.hdr.hdr_len as usize + self.hdr.str_off as usize;
        let start = base + name_off as usize;
        let end = base + self.hdr.str_len as usize;
        let slice = self
            .data
            .get(start..end)
            .ok_or_else(|| anyhow!("string offset {name_off} out of range"))?;
        let nul = slice
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| anyhow!("unterminated string at {name_off}"))?;
        Ok(std::str::from_utf8(&slice[..nul])?)
    }
}
