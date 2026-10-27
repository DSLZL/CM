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
    data.get(start..end)
        .ok_or_else(|| "truncated ELF range".into())
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
    inspect(data, None)
}

pub(super) fn check_declared(data: &[u8], minimum: &str) -> Result<Vec<String>, String> {
    inspect(data, Some(minimum))
}

fn string(strings: &[u8], position: u64) -> Result<&str, String> {
    let tail = strings.get(usize::try_from(position).map_err(|_| "ELF string offset overflow")?..)
        .ok_or("ELF string outside table")?;
    let end = tail.iter().position(|b| *b == 0).ok_or("unterminated ELF string")?;
    std::str::from_utf8(&tail[..end]).map_err(|_| "non-UTF8 ELF string".into())
}

fn version(value: &str) -> Result<Vec<u32>, String> {
    let parts: Vec<_> = value.split('.').collect();
    if value.len() > 32 || !(2..=3).contains(&parts.len()) { return Err("invalid ELF GLIBC version".into()); }
    let mut result: Vec<u32> = parts.into_iter().map(|part| {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) { return Err("invalid ELF GLIBC version".into()); }
        part.parse().map_err(|_| "ELF GLIBC version overflow".into())
    }).collect::<Result<_, String>>()?;
    result.resize(3, 0);
    Ok(result)
}

fn cpu_notes(data: &[u8]) -> Result<(), String> {
    let mut position = 0_u64;
    while position < data.len() as u64 {
        let names = number(data, position, 4)?;
        let size = number(data, position + 4, 4)?;
        let kind = number(data, position + 8, 4)?;
        if names > 64 * 1024 || size > 64 * 1024 { return Err("ELF note exceeds bound".into()); }
        let name = bytes(data, position + 12, names)?;
        let start = position + 12 + names.next_multiple_of(4);
        let descriptor = bytes(data, start, size)?;
        if name == b"GNU\0" && kind == 5 {
            let mut property = 0_u64;
            while property < size {
                let kind = number(descriptor, property, 4)?;
                let length = number(descriptor, property + 4, 4)?;
                let value = bytes(descriptor, property + 8, length)?;
                if kind == 0xc000_8002 {
                    if length != 4 || number(value, 0, 4)? & !1 != 0 {
                        return Err("ELF requires an ISA above the declared x86-64 baseline".into());
                    }
                } else if (0xc000_8000..=0xc000_ffff).contains(&kind) {
                    return Err("unsupported mandatory ELF CPU property".into());
                }
                property = property.checked_add(8 + length.next_multiple_of(8)).ok_or("ELF property overflow")?;
                if property > size { return Err("truncated aligned ELF property".into()); }
            }
        }
        position = start + size.next_multiple_of(4);
        if position > data.len() as u64 { return Err("truncated aligned ELF note".into()); }
    }
    Ok(())
}

fn inspect(data: &[u8], declared: Option<&str>) -> Result<Vec<String>, String> {
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
            4 | 0x6474_e553 => cpu_notes(bytes(data, offset, size)?)?,
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
    let mut version_table = None;
    let mut version_count = None;
    let mut soname = None;
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
            14 if soname.is_none() => soname = Some(value),
            0x6fff_fffe if version_table.is_none() => version_table = Some(value),
            0x6fff_ffff if version_count.is_none() => version_count = Some(value),
            14 | 0x6fff_fffe | 0x6fff_ffff => return Err("duplicate ELF version/SONAME declaration".into()),
            5 | 10 => return Err("duplicate ELF string-table declaration".into()),
            15 | 29 | 0x7fff_fffd | 0x7fff_ffff | 0x6fff_fefb | 0x6fff_fefc => {
                return Err(
                    "P02 rejects RPATH/RUNPATH, filters and native audit resolution".into(),
                );
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
    if let Some(soname) = soname {
        let name = string(strings, soname)?;
        if name.is_empty() || name.len() > 128 || name.contains(['/', '\\']) {
            return Err("invalid ELF SONAME".into());
        }
    }
    let mapped = |address: u64, size: u64| -> Result<u64, String> {
        loads.iter().find_map(|(base, offset, length)| {
            let relative = address.checked_sub(*base)?;
            if relative.checked_add(size)? > *length { return None; }
            offset.checked_add(relative)
        }).ok_or_else(|| "ELF version requirement is not file-backed".into())
    };
    match (version_table, version_count) {
        (None, None) => {}
        (Some(mut address), Some(requirement_count)) if (1..=32).contains(&requirement_count) => {
            let actual = unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) }
                .to_str().map_err(|_| "glibc identity")?;
            let actual = version(actual)?;
            let declared = declared.map(version).transpose()?;
            let mut total = 0;
            for index in 0..requirement_count {
                let entry = mapped(address, 16)?;
                if number(data, entry, 2)? != 1 { return Err("unsupported ELF Verneed version".into()); }
                let count = number(data, entry + 2, 2)?;
                let dependency = string(strings, number(data, entry + 4, 4)?)?;
                if !SYSTEM_LIBRARIES.contains(&dependency) || !(1..=256).contains(&count) {
                    return Err("unsupported ELF version dependency/count".into());
                }
                total += count;
                if total > 1024 { return Err("ELF version requirement budget".into()); }
                let relative = number(data, entry + 8, 4)?;
                if relative < 16 { return Err("invalid ELF Vernaux offset".into()); }
                let mut auxiliary = address.checked_add(relative).ok_or("ELF version offset overflow")?;
                for number_index in 0..count {
                    let item = mapped(auxiliary, 16)?;
                    let name = string(strings, number(data, item + 8, 4)?)?;
                    if let Some(requirement) = name.strip_prefix("GLIBC_") {
                        let requirement = version(requirement)?;
                        if requirement > actual || declared.as_ref().is_some_and(|minimum| &requirement > minimum) {
                            return Err("ELF GLIBC requirement exceeds the declared or current baseline".into());
                        }
                    }
                    let next = number(data, item + 12, 4)?;
                    if (number_index + 1 == count && next != 0) || (number_index + 1 < count && next < 16) {
                        return Err("invalid ELF Vernaux chain".into());
                    }
                    auxiliary = auxiliary.checked_add(next).ok_or("ELF version offset overflow")?;
                }
                let next = number(data, entry + 12, 4)?;
                if (index + 1 == requirement_count && next != 0)
                    || (index + 1 < requirement_count && next < 16) {
                    return Err("invalid ELF Verneed chain".into());
                }
                address = address.checked_add(next).ok_or("ELF version offset overflow")?;
            }
        }
        _ => return Err("invalid ELF version table/count".into()),
    }
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
            let name = std::str::from_utf8(&tail[..end]).map_err(|_| "non-UTF8 ELF dependency")?;
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
    fn actual_cpu_requirements_and_glibc_versions_are_bounded() {
        assert!(version("2.2.5").unwrap() > version("2.2").unwrap());
        assert!(version("2.39").unwrap() > version("2.34").unwrap());
        for bad in ["PRIVATE", "2", "2..3", "2.3.bad", "2.3.4.5"] { assert!(version(bad).is_err()); }
        let mut note = Vec::new();
        for value in [4_u32, 16, 5] { note.extend_from_slice(&value.to_le_bytes()); }
        note.extend_from_slice(b"GNU\0");
        for value in [0xc000_8002_u32, 4, 1, 0] { note.extend_from_slice(&value.to_le_bytes()); }
        cpu_notes(&note).unwrap();
        note[24] = 2;
        assert!(cpu_notes(&note).is_err());
        note[24] = 1;
        for end in 1..note.len() { assert!(cpu_notes(&note[..end]).is_err()); }
    }

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
