use object::endian::LittleEndian as LE;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, ImageThunkData, PeFile64};
use std::ops::Range;

const MAX_FILE: usize = 32 * 1024 * 1024;
const MAX_IMPORTS: usize = 4096;
const SYSTEM_DLLS: &[&str] = &[
    "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "crypt32.dll",
    "iphlpapi.dll", "kernel32.dll", "kernelbase.dll", "mswsock.dll", "ntdll.dll",
    "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "secur32.dll", "shell32.dll",
    "user32.dll", "userenv.dll", "ucrtbase.dll", "version.dll", "winhttp.dll",
    "ws2_32.dll", "api-ms-win-core-synch-l1-2-0.dll",
];

#[derive(Debug)]
pub struct Audit {
    pub dependencies: Vec<String>,
    pub imports: usize,
    pub ordinal_imports: usize,
    pub entry_rva: u32,
}

struct Section {
    memory: Range<u32>,
    raw: Range<usize>,
    flags: u32,
}

struct Image<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
}

impl<'a> Image<'a> {
    fn data(&self, rva: u32, size: u32) -> Result<&'a [u8], &'static str> {
        let end = rva.checked_add(size).ok_or("PE RVA overflow")?;
        let section = self.sections.iter().find(|section| {
            rva >= section.memory.start && end <= section.memory.end
                && u64::from(end - section.memory.start) <= section.raw.len() as u64
        }).ok_or("PE RVA is not file backed")?;
        let start = section.raw.start + (rva - section.memory.start) as usize;
        self.bytes.get(start..start + size as usize).ok_or("PE file range")
    }

    fn string(&self, rva: u32, limit: usize) -> Result<&'a [u8], &'static str> {
        let section = self.sections.iter().find(|section| {
            rva >= section.memory.start && rva < section.memory.end
                && (rva - section.memory.start) < section.raw.len() as u32
        }).ok_or("PE string RVA")?;
        let start = section.raw.start + (rva - section.memory.start) as usize;
        let remaining = (section.memory.end - rva) as usize;
        let end = section.raw.end.min(start + remaining).min(start + limit + 1);
        let data = &self.bytes[start..end];
        let length = data.iter().position(|byte| *byte == 0).ok_or("PE string terminator")?;
        if length == 0 || !data[..length].iter().all(|byte| (33..=126).contains(byte)) {
            return Err("PE string encoding");
        }
        Ok(&data[..length])
    }

    fn executable(&self, rva: u32) -> bool {
        self.sections.iter().any(|section| {
            section.memory.contains(&rva)
                && rva - section.memory.start < section.raw.len() as u32
                && section.flags & 0xe000_0000 == 0x6000_0000
        })
    }
}

fn overlap<T: Ord>(left: &Range<T>, right: &Range<T>) -> bool {
    left.start < right.end && right.start < left.end
}

/// Validate native DLL metadata before any system loader or constructor runs.
/// This function does not establish retained-byte or resolved-module identity.
pub fn check(bytes: &[u8], machine: u16, required_entry: &str) -> Result<Audit, &'static str> {
    if bytes.len() > MAX_FILE || !matches!(machine, 0x8664 | 0xaa64)
        || !matches!(required_entry, "cm_mod_entry_v1" | "cm_mod_entry_v2") {
        return Err("PE input policy");
    }
    let file = PeFile64::parse(bytes).map_err(|_| "PE headers")?;
    let header = file.nt_headers();
    let coff = header.file_header();
    let optional = header.optional_header();
    let count = usize::from(coff.number_of_sections.get(LE));
    let nt_offset = file.dos_header().nt_headers_offset() as usize;
    let file_align = optional.file_alignment();
    let section_align = optional.section_alignment();
    let headers = optional.size_of_headers();
    let image_size = optional.size_of_image();
    if coff.machine.get(LE) != machine || coff.characteristics.get(LE) & 0x2002 != 0x2002 {
        return Err("PE native DLL required");
    }
    if !(1..=96).contains(&count) || nt_offset < 64 || !nt_offset.is_multiple_of(4)
        || coff.size_of_optional_header.get(LE) != 240
        || optional.number_of_rva_and_sizes() != 16
        || coff.pointer_to_symbol_table.get(LE) != 0 || coff.number_of_symbols.get(LE) != 0
        || !file_align.is_power_of_two() || !(512..=65536).contains(&file_align)
        || !section_align.is_power_of_two() || !(4096..=65536).contains(&section_align)
        || section_align < file_align || !headers.is_multiple_of(file_align)
        || headers as usize > bytes.len() || nt_offset + 264 + count * 40 > headers as usize
        || image_size == 0 || image_size > 256 * 1024 * 1024
        || !image_size.is_multiple_of(section_align)
        || !optional.image_base().is_multiple_of(65536)
        || optional.dll_characteristics() & 0x0140 != 0x0140 {
        return Err("PE header bounds or protections");
    }
    let mut image = Image { bytes, sections: Vec::with_capacity(count) };
    for section in file.section_table().iter() {
        let start = section.virtual_address.get(LE);
        let raw_start = section.pointer_to_raw_data.get(LE) as usize;
        let raw_size = section.size_of_raw_data.get(LE);
        let size = section.virtual_size.get(LE).max(raw_size);
        let end = start.checked_add(size).ok_or("PE section overflow")?;
        let raw_end = raw_start.checked_add(raw_size as usize).ok_or("PE raw overflow")?;
        let flags = section.characteristics.get(LE);
        let candidate = Section { memory: start..end, raw: raw_start..raw_end, flags };
        if size == 0 || start < headers || !start.is_multiple_of(section_align) || end > image_size
            || raw_end > bytes.len() || !raw_size.is_multiple_of(file_align)
            || (raw_size != 0 && (raw_start < headers as usize || !raw_start.is_multiple_of(file_align as usize)))
            || (raw_size == 0 && raw_start != 0)
            || flags & 0xa000_0000 == 0xa000_0000
            || section.pointer_to_relocations.get(LE) != 0 || section.pointer_to_linenumbers.get(LE) != 0
            || section.number_of_relocations.get(LE) != 0 || section.number_of_linenumbers.get(LE) != 0
            || image.sections.iter().any(|old| {
                overlap(&old.memory, &candidate.memory)
                    || (!old.raw.is_empty() && !candidate.raw.is_empty() && overlap(&old.raw, &candidate.raw))
            }) {
            return Err("PE section bounds, overlap or protections");
        }
        image.sections.push(candidate);
    }
    if optional.address_of_entry_point() != 0 && !image.executable(optional.address_of_entry_point()) {
        return Err("PE DLL entry RVA");
    }
    let mut directories = [(0u32, 0u32); 16];
    for (index, directory) in file.data_directories().enumerate() {
        let rva = directory.virtual_address.get(LE);
        let size = directory.size.get(LE);
        if (rva == 0) != (size == 0) {
            return Err("PE directory pair");
        }
        directories[index] = (rva, size);
        if size != 0 {
            if index == 4 {
                let end = u64::from(rva) + u64::from(size);
                if rva < headers || !rva.is_multiple_of(8) || size < 8 || end > bytes.len() as u64
                    || image.sections.iter().any(|section| {
                        overlap(&section.raw, &(rva as usize..end as usize))
                    }) {
                    return Err("PE certificate range");
                }
            } else {
                image.data(rva, size)?;
            }
        }
    }
    // The delay helper has its own lookup behavior; reject it until its closure is pinned.
    if [7, 8, 11, 13, 14, 15].iter().any(|index| directories[*index] != (0, 0)) {
        return Err("PE unsupported bound, delay, managed or reserved directory");
    }
    let mut audit = Audit { dependencies: Vec::new(), imports: 0, ordinal_imports: 0, entry_rva: 0 };
    let (import_rva, import_size) = directories[1];
    let (iat_rva, iat_size) = directories[12];
    if (import_rva == 0) != (iat_rva == 0) {
        return Err("PE import and IAT pair");
    }
    if import_rva != 0 {
        if !(40..=33 * 20).contains(&import_size) || !import_size.is_multiple_of(20)
            || iat_size > (MAX_IMPORTS as u32 + 32) * 8 || !iat_size.is_multiple_of(8) {
            return Err("PE import table bounds");
        }
        let table = file.import_table().map_err(|_| "PE imports")?.ok_or("PE missing imports")?;
        let mut descriptors = table.descriptors().map_err(|_| "PE import descriptors")?;
        let mut terminated = false;
        let mut iat_ranges = Vec::new();
        for index in 0..import_size / 20 {
            let Some(descriptor) = descriptors.next().map_err(|_| "PE import descriptor")? else {
                let tail = image.data(import_rva + index * 20, import_size - index * 20)?;
                if tail.iter().any(|byte| *byte != 0) {
                    return Err("PE data after null import");
                }
                terminated = true;
                break;
            };
            if audit.dependencies.len() == 32 || descriptor.time_date_stamp.get(LE) != 0
                || !matches!(descriptor.forwarder_chain.get(LE), 0 | u32::MAX) {
                return Err("PE bound import or dependency count");
            }
            let name = image.string(descriptor.name.get(LE), 128)?;
            if table.name(descriptor.name.get(LE)).map_err(|_| "PE import name")? != name {
                return Err("PE import name mismatch");
            }
            let name = std::str::from_utf8(name).map_err(|_| "PE DLL name")?.to_ascii_lowercase();
            if !SYSTEM_DLLS.contains(&name.as_str()) || audit.dependencies.contains(&name) {
                return Err("PE dependency is not a unique permitted system DLL");
            }
            let iat = descriptor.first_thunk.get(LE);
            let lookup = match descriptor.original_first_thunk.get(LE) { 0 => iat, value => value };
            if lookup == 0 || !lookup.is_multiple_of(8) || !iat.is_multiple_of(8) {
                return Err("PE import thunk alignment");
            }
            let thunks = table.thunks(lookup).map_err(|_| "PE import thunks")?;
            let mut thunk_end = None;
            for index in 0..=MAX_IMPORTS {
                let offset = index as u32 * 8;
                let at = lookup.checked_add(offset).ok_or("PE lookup overflow")?;
                let slot = iat.checked_add(offset).ok_or("PE IAT overflow")?;
                let raw = u64::from_le_bytes(image.data(at, 8)?.try_into().map_err(|_| "PE thunk width")?);
                let actual = u64::from_le_bytes(image.data(slot, 8)?.try_into().map_err(|_| "PE IAT width")?);
                let thunk = thunks.get::<object::pe::ImageNtHeaders64>(index).map_err(|_| "PE thunk")?;
                if raw != thunk.raw() || actual != raw {
                    return Err("PE bound or inconsistent IAT");
                }
                if raw == 0 {
                    thunk_end = Some(slot + 8);
                    break;
                }
                if audit.imports == MAX_IMPORTS {
                    return Err("PE import count");
                }
                if thunk.is_ordinal() {
                    if raw & 0x7fff_ffff_ffff_0000 != 0 || thunk.ordinal() == 0 {
                        return Err("PE ordinal import encoding");
                    }
                    audit.ordinal_imports += 1;
                } else {
                    if raw > 0x7fff_ffff {
                        return Err("PE named import RVA");
                    }
                    image.data(raw as u32, 2)?;
                    let name = image.string(raw as u32 + 2, 512)?;
                    if table.hint_name(raw as u32).map_err(|_| "PE hint/name")?.1 != name {
                        return Err("PE named import mismatch");
                    }
                }
                audit.imports += 1;
            }
            let end = thunk_end.ok_or("PE missing null thunk")?;
            let range = iat..end;
            if iat < iat_rva || u64::from(end) > u64::from(iat_rva) + u64::from(iat_size)
                || iat_ranges.iter().any(|old| overlap(old, &range)) {
                return Err("PE IAT range or overlap");
            }
            iat_ranges.push(range);
            audit.dependencies.push(name);
        }
        if !terminated {
            return Err("PE missing null import descriptor");
        }
    }
    let exports = file.export_table().map_err(|_| "PE exports")?.ok_or("PE missing entry export")?;
    let directory = exports.directory();
    if exports.addresses().is_empty() || exports.addresses().len() > 4096
        || exports.name_pointers().is_empty() || exports.name_pointers().len() > 4096
        || directory.number_of_functions.get(LE) as usize != exports.addresses().len()
        || directory.number_of_names.get(LE) as usize != exports.name_pointers().len()
        || exports.ordinal_base().checked_add(exports.addresses().len() as u32).is_none() {
        return Err("PE export counts");
    }
    image.string(directory.name.get(LE), 128)?;
    for address in exports.addresses() {
        let address = address.get(LE);
        if address != 0 && (exports.is_forward(address)
            || !image.sections.iter().any(|section| section.memory.contains(&address))) {
            return Err("PE forwarded or unmapped export");
        }
    }
    let mut previous: &[u8] = &[];
    for (pointer, ordinal) in exports.name_iter() {
        let name = image.string(pointer, 512)?;
        if name <= previous || exports.name_from_pointer(pointer).map_err(|_| "PE export name")? != name {
            return Err("PE unsorted or invalid export name");
        }
        previous = name;
        let address = exports.address_by_index(u32::from(ordinal)).map_err(|_| "PE export ordinal")?;
        if address == 0 {
            return Err("PE null named export");
        }
        if name == required_entry.as_bytes() {
            if !image.executable(address) {
                return Err("PE entry is not executable");
            }
            audit.entry_rva = address;
        }
    }
    if audit.entry_rva == 0 {
        return Err("PE missing required entry");
    }
    audit.dependencies.sort();
    Ok(audit)
}
