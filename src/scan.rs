//! Finding files and opening the object files inside them.
//!
//! A path is either a single file or a glob. A universal (fat) Mach-O yields one
//! object per architecture; everything else yields one object per file.

use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
use object::{FileKind, Object};
use duckdb_tables::BoxError;
use std::{fs::File, path::PathBuf};

pub fn is_glob(pattern: &str) -> bool {
    pattern.contains(['*', '?', '[', '{'])
}

/// Expands `{a,b}` alternatives (nested too), which the glob crate doesn't support.
/// A brace without a matching close is left as a literal.
fn expand_braces(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_string()];
    };
    let (mut depth, mut close, mut commas) = (0, None, Vec::new());
    for (i, c) in pattern[open..].char_indices().map(|(i, c)| (open + i, c)) {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            ',' if depth == 1 => commas.push(i),
            _ => {}
        }
    }
    let Some(close) = close else {
        return vec![pattern.to_string()];
    };
    let (head, tail) = (&pattern[..open], &pattern[close + 1..]);
    let bounds: Vec<usize> = std::iter::once(open).chain(commas).chain(std::iter::once(close)).collect();
    bounds
        .windows(2)
        .flat_map(|w| expand_braces(&format!("{head}{}{tail}", &pattern[w[0] + 1..w[1]])))
        .collect()
}

/// Expands a glob into regular files, sorted and deduplicated for deterministic output.
/// A plain path is returned as-is so a missing file is reported when it is opened.
pub fn expand(pattern: &str) -> Result<Vec<PathBuf>, BoxError> {
    if !is_glob(pattern) {
        return Ok(vec![PathBuf::from(pattern)]);
    }
    let mut paths = Vec::new();
    for p in expand_braces(pattern) {
        paths.extend(glob::glob(&p)?.filter_map(Result::ok).filter(|p| p.is_file()));
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_braces() {
        assert_eq!(expand_braces("/usr/{bin,sbin}/*"), ["/usr/bin/*", "/usr/sbin/*"]);
        assert_eq!(expand_braces("a{b,c{d,e}}f"), ["abf", "acdf", "acef"]);
        assert_eq!(expand_braces("{a,b}{1,2}"), ["a1", "a2", "b1", "b2"]);
        assert_eq!(expand_braces("x{,.so}"), ["x", "x.so"]);
        assert_eq!(expand_braces("no-close{a,b"), ["no-close{a,b"]);
        assert_eq!(expand_braces("plain"), ["plain"]);
    }
}

/// Everything a table needs to know about one object.
pub struct Ctx<'a> {
    pub path: &'a str,
    pub arch: String,
    pub file: &'a object::File<'a>,
    /// The bytes of this object: the whole file, or one slice of a fat Mach-O.
    pub data: &'a [u8],
    pub file_size: u64,
}

/// Opens `path` and calls `f` for each object in it. Non-object files are an error.
pub fn for_each_object(
    path: &PathBuf,
    mut f: impl FnMut(&Ctx) -> Result<(), BoxError>,
) -> Result<(), BoxError> {
    let path_str = path.to_string_lossy();
    let file = File::open(path).map_err(|e| format!("{path_str}: {e}"))?;
    let file_size = file.metadata()?.len();
    if file_size == 0 {
        return Err(format!("{path_str}: empty file").into());
    }
    // Safety: the map is read-only and dropped before this function returns. A file
    // truncated concurrently could fault, the same trade-off every mmap-based tool makes.
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let data: &[u8] = &mmap;

    let slices: Vec<&[u8]> = match FileKind::parse(data) {
        Ok(FileKind::MachOFat32) => fat_slices(MachOFatFile32::parse(data)?.arches(), data)?,
        Ok(FileKind::MachOFat64) => fat_slices(MachOFatFile64::parse(data)?.arches(), data)?,
        Ok(
            FileKind::Elf32
            | FileKind::Elf64
            | FileKind::MachO32
            | FileKind::MachO64
            | FileKind::Pe32
            | FileKind::Pe64
            | FileKind::Coff
            | FileKind::CoffBig,
        ) => vec![data],
        Ok(other) => return Err(format!("{path_str}: unsupported file kind {other:?}").into()),
        Err(_) => return Err(format!("{path_str}: not an ELF, Mach-O or PE file").into()),
    };

    for slice in slices {
        let obj = object::File::parse(slice).map_err(|e| format!("{path_str}: {e}"))?;
        let ctx = Ctx {
            path: &path_str,
            arch: arch_name(&obj),
            file: &obj,
            data: slice,
            file_size,
        };
        f(&ctx)?;
    }
    Ok(())
}

fn fat_slices<'d, A: FatArch>(arches: &[A], data: &'d [u8]) -> Result<Vec<&'d [u8]>, BoxError> {
    arches
        .iter()
        .map(|a| a.data(data).map_err(Into::into))
        .collect()
}

/// Short, conventional names: x86_64, aarch64, i386, arm, riscv64, ...
fn arch_name(obj: &object::File) -> String {
    use object::Architecture as A;
    match obj.architecture() {
        A::X86_64 | A::X86_64_X32 => "x86_64".into(),
        A::I386 => "i386".into(),
        A::Aarch64 | A::Aarch64_Ilp32 => "aarch64".into(),
        A::Arm => "arm".into(),
        A::Riscv64 => "riscv64".into(),
        A::Riscv32 => "riscv32".into(),
        other => format!("{other:?}").to_lowercase(),
    }
}
