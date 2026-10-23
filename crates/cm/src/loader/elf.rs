// Bounded ELF64 program-header/dynamic-table inspection, before any native code.
const SYSTEM_LIBRARIES: &[&str] = &[
    "libc.so.6",
    "libgcc_s.so.1",
    "libm.so.6",
    "libpthread.so.0",
    "libdl.so.2",
    "librt.so.1",
    "ld-linux-x86-64.so.2",
];

fn bytes(data: &[u8], offset: u64, size: u64) -> Result<&[u8], String> {
    let end = offset.checked_add(size).ok_or("ELF range overflow")?;
    let start = usize::try_from(offset).map_err(|_| "ELF offset overflow")?;
    let end = usize::try_from(end).map_err(|_| "ELF size overflow")?;
    data.get(start..end).ok_or_else(|| "truncated ELF range".into())
}

fn number(data: &[u8], offset: u64, size: u64) -> Result<u64, String> {
    Ok(bytes(data, offset, size)?
        .iter()
        .enumerate()
        .fold(0, |value, (shift, byte)| {
            value | (u64::from(*byte) << (shift * 8))
        }))
}

pub(super) fn check(data: &[u8]) -> Result<Vec<String>, String> {
    if bytes(data, 0, 7)? != b"\x7fELF\x02\x01\x01"
        || ![0, 3].contains(&number(data, 7, 1)?)
        || number(data, 16, 2)? != 3
        || number(data, 18, 2)? != 62
        || number(data, 20, 4)? != 1
        || number(data, 52, 2)? != 64
        || number(data, 54, 2)? != 56
    {
        return Err("expected ELF64 little-endian x86_64 shared object".into());
    }
    let start = number(data, 32, 8)?;
    let count = number(data, 56, 2)?;
    if !(1..=256).contains(&count) {
        return Err("unsupported ELF program-header count".into());
    }
    bytes(data, start, count * 56)?;
    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..count {
        let header = start + index * 56;
        let kind = number(data, header, 4)?;
        let offset = number(data, header + 8, 8)?;
        let address = number(data, header + 16, 8)?;
        let size = number(data, header + 32, 8)?;
        bytes(data, offset, size)?;
        match kind {
            1 => loads.push((address, offset, size)),
            2 if dynamic.is_none() => dynamic = Some((offset, size)),
            2 => return Err("duplicate ELF dynamic segment".into()),
            3 => return Err("ELF executable interpreter is not a Mod library".into()),
            _ => {}
        }
    }
    let (offset, size) = dynamic.ok_or("missing ELF dynamic segment")?;
    if !size.is_multiple_of(16) || size > 64 * 1024 {
        return Err("invalid ELF dynamic segment size".into());
    }
    let mut needed = Vec::new();
    let mut table = None;
    let mut table_size = None;
    let mut terminated = false;
    for index in 0..size / 16 {
        let tag = number(data, offset + index * 16, 8)?;
        let value = number(data, offset + index * 16 + 8, 8)?;
        match tag {
            0 => {
                terminated = true;
                break;
            }
            1 => needed.push(value),
            5 if table.is_none() => table = Some(value),
            10 if table_size.is_none() => table_size = Some(value),
            5 | 10 => return Err("duplicate ELF string-table declaration".into()),
            15 | 29 | 0x7fff_fffd | 0x7fff_ffff | 0x6fff_fefb | 0x6fff_fefc => {
                return Err("P02 rejects RPATH/RUNPATH, filters and native audit resolution".into());
            }
            _ => {}
        }
    }
    if !terminated || needed.len() > 32 {
        return Err("unterminated or excessive ELF dynamic declarations".into());
    }
    let address = table.ok_or("missing ELF dynamic string table")?;
    let size = table_size.ok_or("missing ELF dynamic string-table size")?;
    if size > 4 * 1024 * 1024 {
        return Err("ELF dynamic string table too large".into());
    }
    let offset = loads
        .iter()
        .find_map(|(base, offset, length)| {
            let relative = address.checked_sub(*base)?;
            if relative.checked_add(size)? > *length {
                return None;
            }
            offset.checked_add(relative)
        })
        .ok_or("ELF string table is not in a file-backed LOAD segment")?;
    let strings = bytes(data, offset, size)?;
    needed
        .into_iter()
        .map(|position| {
            let position = usize::try_from(position).map_err(|_| "ELF string offset overflow")?;
            let tail = strings
                .get(position..)
                .ok_or("ELF dependency string outside table")?;
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .ok_or("unterminated ELF dependency")?;
            let name =
                std::str::from_utf8(&tail[..end]).map_err(|_| "non-UTF8 ELF dependency")?;
            if !SYSTEM_LIBRARIES.contains(&name) {
                return Err(format!("unsupported native dependency: {name}"));
            }
            Ok(name.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_and_wrong_architecture_are_rejected() {
        for data in [&b""[..], &b"not an ELF"[..], &b"\x7fELF\x01\x01\x01"[..]] {
            assert!(check(data).is_err());
        }
        let mut header = vec![0; 64];
        header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        header[16] = 3;
        header[18] = 183;
        assert!(check(&header).is_err());
    }
}
