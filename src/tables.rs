//! Table definitions. Each table turns one object into owned items, and lists its
//! columns as (name, type, doc, getter). Getters run only for projected columns, so costly
//! ones (demangling) are free when a query doesn't select them.

use crate::scan::Ctx;
use duckdb_tables::{BoxError, Cell, ColType, Column};
use object::{
    Endianness, NameOrOrdinal, Object, ObjectSection, ObjectSegment, ObjectSymbol,
    ObjectSymbolTable, macho, read::ImportFlags, read::ImportLibraryFlags,
};
use std::{ops::Deref, sync::Arc};

/// An item plus the object it came from. Derefs to the item, so getters read its fields directly.
pub struct Obj<T> {
    pub path: Arc<str>,
    pub arch: Arc<str>,
    pub item: T,
}

impl<T> Deref for Obj<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.item
    }
}

/// A table's columns, after `path` and `arch`, which every table starts with so rows
/// from many files can be told apart.
macro_rules! columns {
    ($($column:expr),* $(,)?) => {
        &[
            Column {
                name: "path",
                ty: ColType::Varchar,
                doc: "The file.",
                get: |o| Cell::Str(o.path.to_string()),
            },
            Column {
                name: "arch",
                ty: ColType::Varchar,
                doc: "Architecture: x86_64, aarch64, i386, arm, riscv64, ...",
                get: |o| Cell::Str(o.arch.to_string()),
            },
            $($column),*
        ]
    };
}

pub struct Options {
    /// Minimum run length for `binary_strings`.
    pub min_length: usize,
}

pub trait Table: 'static {
    type Item: 'static;
    fn doc() -> &'static str;
    fn columns() -> &'static [Column<Obj<Self::Item>>];
    fn items(ctx: &Ctx, opts: &Options) -> Result<Vec<Self::Item>, BoxError>;
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn debug_lower(v: impl std::fmt::Debug) -> String {
    format!("{v:?}").to_lowercase()
}

fn str_cell(s: &str) -> Cell {
    Cell::Str(s.to_string())
}

// ---------------------------------------------------------------------------
// binary_info: one row per object
// ---------------------------------------------------------------------------

pub struct Info {
    format: &'static str,
    kind: String,
    bits: i64,
    endian: &'static str,
    entry: u64,
    build_id: Option<String>,
    interpreter: Option<String>,
    soname: Option<String>,
    rpath: Option<String>,
    runpath: Option<String>,
    has_symbols: bool,
    has_debug_info: bool,
    size: u64,
    file_size: u64,
}

#[derive(Default)]
struct Dynamic {
    interpreter: Option<String>,
    soname: Option<String>,
    rpath: Option<String>,
    runpath: Option<String>,
}

fn elf_dynamic<'d, E>(f: &object::read::elf::ElfFile<'d, E, &'d [u8]>) -> Dynamic
where
    E: object::read::elf::FileHeader<Endian = Endianness>,
{
    use object::read::elf::ProgramHeader;
    let mut out = Dynamic {
        interpreter: f
            .elf_program_headers()
            .iter()
            .find_map(|ph| ph.interpreter(f.endian(), f.data()).ok().flatten())
            .map(lossy),
        ..Default::default()
    };
    if let Ok(table) = f.elf_dynamic_table() {
        for d in table.iter() {
            let value = || table.string(d).ok().map(lossy);
            if d.tag == object::elf::DT_SONAME {
                out.soname = value();
            } else if d.tag == object::elf::DT_RPATH {
                out.rpath = value();
            } else if d.tag == object::elf::DT_RUNPATH {
                out.runpath = value();
            }
        }
    }
    out
}

/// Mach-O equivalents: the install name is the soname, LC_RPATHs join like an ELF rpath,
/// and the dylinker (normally /usr/lib/dyld) is the interpreter.
fn macho_dynamic<'d, M>(f: &object::read::macho::MachOFile<'d, M, &'d [u8]>) -> Dynamic
where
    M: object::read::macho::MachHeader<Endian = Endianness>,
{
    use object::read::macho::LoadCommandVariant as V;
    let endian = f.endian();
    let mut out = Dynamic::default();
    let mut rpaths = Vec::new();
    if let Ok(mut commands) = f.macho_load_commands() {
        while let Ok(Some(cmd)) = commands.next() {
            match cmd.variant() {
                Ok(V::IdDylib(d)) => out.soname = cmd.string(endian, d.dylib.name).ok().map(lossy),
                Ok(V::LoadDylinker(d)) => {
                    out.interpreter = cmd.string(endian, d.name).ok().map(lossy)
                }
                Ok(V::Rpath(r)) => rpaths.extend(cmd.string(endian, r.path).ok().map(lossy)),
                _ => {}
            }
        }
    }
    out.rpath = (!rpaths.is_empty()).then(|| rpaths.join(":"));
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct InfoTable;

impl Table for InfoTable {
    type Item = Info;

    fn doc() -> &'static str {
        "One row per object: format, kind, linking and debug info. A universal Mach-O gives one row per architecture."
    }

    fn columns() -> &'static [Column<Obj<Info>>] {
        static COLUMNS: &[Column<Obj<Info>>] = columns![
            Column {
                name: "format",
                ty: ColType::Varchar,
                doc: "elf, macho, pe or coff.",
                get: |i| str_cell(i.format),
            },
            Column {
                name: "kind",
                ty: ColType::Varchar,
                doc: "executable, dynamic, relocatable or core. PIE executables are executable, as file(1) reports them.",
                get: |i| Cell::Str(i.kind.clone()),
            },
            Column {
                name: "bits",
                ty: ColType::Bigint,
                doc: "32 or 64.",
                get: |i| Cell::Int(i.bits),
            },
            Column {
                name: "endian",
                ty: ColType::Varchar,
                doc: "little or big.",
                get: |i| str_cell(i.endian),
            },
            Column {
                name: "entry",
                ty: ColType::Ubigint,
                doc: "Entry point address.",
                get: |i| Cell::UInt(i.entry),
            },
            Column {
                name: "build_id",
                ty: ColType::Varchar,
                doc: "ELF GNU build ID in hex, or the Mach-O UUID.",
                get: |i| i.build_id.clone().into(),
            },
            Column {
                name: "interpreter",
                ty: ColType::Varchar,
                doc: "ELF PT_INTERP, or the Mach-O dylinker.",
                get: |i| i.interpreter.clone().into(),
            },
            Column {
                name: "soname",
                ty: ColType::Varchar,
                doc: "ELF DT_SONAME, or the Mach-O install name.",
                get: |i| i.soname.clone().into(),
            },
            Column {
                name: "rpath",
                ty: ColType::Varchar,
                doc: "ELF DT_RPATH, or Mach-O LC_RPATH entries joined with ':'.",
                get: |i| i.rpath.clone().into(),
            },
            Column {
                name: "runpath",
                ty: ColType::Varchar,
                doc: "ELF DT_RUNPATH.",
                get: |i| i.runpath.clone().into(),
            },
            Column {
                name: "has_symbols",
                ty: ColType::Boolean,
                doc: "Has a non-empty symbol table.",
                get: |i| Cell::Bool(i.has_symbols),
            },
            Column {
                name: "has_debug_info",
                ty: ColType::Boolean,
                doc: "Has debug info.",
                get: |i| Cell::Bool(i.has_debug_info),
            },
            Column {
                name: "size",
                ty: ColType::Ubigint,
                doc: "Bytes in this object: the whole file, or one slice of a universal Mach-O.",
                get: |i| Cell::UInt(i.size),
            },
            Column {
                name: "file_size",
                ty: ColType::Ubigint,
                doc: "Bytes in the whole file.",
                get: |i| Cell::UInt(i.file_size),
            },
        ];
        COLUMNS
    }

    fn items(ctx: &Ctx, _: &Options) -> Result<Vec<Info>, BoxError> {
        let f = ctx.file;
        let dynamic = match f {
            object::File::Elf32(e) => elf_dynamic(e),
            object::File::Elf64(e) => elf_dynamic(e),
            object::File::MachO32(m) => macho_dynamic(m),
            object::File::MachO64(m) => macho_dynamic(m),
            _ => Dynamic::default(),
        };
        // ELF build IDs are hex; Mach-O LC_UUIDs are shown in the usual UUID form.
        let build_id = match f.build_id().ok().flatten() {
            Some(id) => Some(hex(id)),
            None => f.mach_uuid().ok().flatten().map(|u| {
                let h = hex(&u);
                format!(
                    "{}-{}-{}-{}-{}",
                    &h[..8],
                    &h[8..12],
                    &h[12..16],
                    &h[16..20],
                    &h[20..]
                )
            }),
        };
        Ok(vec![Info {
            format: match f.format() {
                object::BinaryFormat::Elf => "elf",
                object::BinaryFormat::MachO => "macho",
                object::BinaryFormat::Pe => "pe",
                object::BinaryFormat::Coff => "coff",
                _ => "other",
            },
            // PIE executables are ET_DYN like shared libraries; like file(1), treat an
            // ET_DYN with a program interpreter as an executable.
            kind: match f.kind() {
                object::ObjectKind::Dynamic if dynamic.interpreter.is_some() => "executable".into(),
                other => debug_lower(other),
            },
            bits: if f.is_64() { 64 } else { 32 },
            endian: if f.is_little_endian() {
                "little"
            } else {
                "big"
            },
            entry: f.entry(),
            build_id,
            interpreter: dynamic.interpreter,
            soname: dynamic.soname,
            rpath: dynamic.rpath,
            runpath: dynamic.runpath,
            has_symbols: f
                .symbol_table()
                .is_some_and(|t| t.symbols().next().is_some()),
            has_debug_info: f.has_debug_symbols(),
            size: ctx.data.len() as u64,
            file_size: ctx.file_size,
        }])
    }
}

// ---------------------------------------------------------------------------
// binary_sections
// ---------------------------------------------------------------------------

pub struct Section {
    name: String,
    segment: Option<String>,
    kind: String,
    address: u64,
    size: u64,
    file_offset: Option<u64>,
    file_size: Option<u64>,
    align: u64,
}

pub struct SectionsTable;

impl Table for SectionsTable {
    type Item = Section;

    fn doc() -> &'static str {
        "Sections of each object."
    }

    fn columns() -> &'static [Column<Obj<Section>>] {
        static COLUMNS: &[Column<Obj<Section>>] = columns![
            Column {
                name: "name",
                ty: ColType::Varchar,
                doc: "Section name.",
                get: |s| Cell::Str(s.name.clone()),
            },
            Column {
                name: "segment",
                ty: ColType::Varchar,
                doc: "Mach-O segment containing the section; NULL for other formats.",
                get: |s| s.segment.clone().into(),
            },
            Column {
                name: "kind",
                ty: ColType::Varchar,
                doc: "text, data, read_only_data, uninitialized_data, debug, ...",
                get: |s| Cell::Str(s.kind.clone()),
            },
            Column {
                name: "address",
                ty: ColType::Ubigint,
                doc: "Virtual address.",
                get: |s| Cell::UInt(s.address),
            },
            Column {
                name: "size",
                ty: ColType::Ubigint,
                doc: "Size in memory.",
                get: |s| Cell::UInt(s.size),
            },
            Column {
                name: "file_offset",
                ty: ColType::Ubigint,
                doc: "Offset in the file; NULL if the section isn't stored in the file.",
                get: |s| s.file_offset.into(),
            },
            Column {
                name: "file_size",
                ty: ColType::Ubigint,
                doc: "Bytes stored in the file; NULL if not stored.",
                get: |s| s.file_size.into(),
            },
            Column {
                name: "align",
                ty: ColType::Ubigint,
                doc: "Alignment in bytes.",
                get: |s| Cell::UInt(s.align),
            },
        ];
        COLUMNS
    }

    fn items(ctx: &Ctx, _: &Options) -> Result<Vec<Section>, BoxError> {
        Ok(ctx
            .file
            .sections()
            .map(|s| {
                let range = s.file_range();
                Section {
                    name: s.name_bytes().map(lossy).unwrap_or_default(),
                    segment: s.segment_name_bytes().ok().flatten().map(lossy),
                    kind: debug_lower(s.kind()),
                    address: s.address(),
                    size: s.size(),
                    file_offset: range.map(|r| r.0),
                    file_size: range.map(|r| r.1),
                    align: s.align(),
                }
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// binary_segments
// ---------------------------------------------------------------------------

pub struct Segment {
    name: Option<String>,
    address: u64,
    size: u64,
    file_offset: u64,
    file_size: u64,
    r: bool,
    w: bool,
    x: bool,
}

pub struct SegmentsTable;

impl Table for SegmentsTable {
    type Item = Segment;

    fn doc() -> &'static str {
        "Segments (ELF program headers, Mach-O segments) with their permissions."
    }

    fn columns() -> &'static [Column<Obj<Segment>>] {
        static COLUMNS: &[Column<Obj<Segment>>] = columns![
            Column {
                name: "name",
                ty: ColType::Varchar,
                doc: "Segment name (Mach-O); NULL for ELF.",
                get: |s| s.name.clone().into(),
            },
            Column {
                name: "address",
                ty: ColType::Ubigint,
                doc: "Virtual address.",
                get: |s| Cell::UInt(s.address),
            },
            Column {
                name: "size",
                ty: ColType::Ubigint,
                doc: "Size in memory.",
                get: |s| Cell::UInt(s.size),
            },
            Column {
                name: "file_offset",
                ty: ColType::Ubigint,
                doc: "Offset in the file.",
                get: |s| Cell::UInt(s.file_offset),
            },
            Column {
                name: "file_size",
                ty: ColType::Ubigint,
                doc: "Bytes stored in the file.",
                get: |s| Cell::UInt(s.file_size),
            },
            Column {
                name: "r",
                ty: ColType::Boolean,
                doc: "Readable.",
                get: |s| Cell::Bool(s.r),
            },
            Column {
                name: "w",
                ty: ColType::Boolean,
                doc: "Writable.",
                get: |s| Cell::Bool(s.w),
            },
            Column {
                name: "x",
                ty: ColType::Boolean,
                doc: "Executable.",
                get: |s| Cell::Bool(s.x),
            },
        ];
        COLUMNS
    }

    fn items(ctx: &Ctx, _: &Options) -> Result<Vec<Segment>, BoxError> {
        Ok(ctx
            .file
            .segments()
            .map(|s| {
                let (file_offset, file_size) = s.file_range();
                let p = s.permissions();
                Segment {
                    name: s.name_bytes().ok().flatten().map(lossy),
                    address: s.address(),
                    size: s.size(),
                    file_offset,
                    file_size,
                    r: p.readable(),
                    w: p.writable(),
                    x: p.executable(),
                }
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// binary_symbols
// ---------------------------------------------------------------------------

pub struct Symbol {
    name: String,
    kind: String,
    scope: String,
    defined: bool,
    global: bool,
    weak: bool,
    address: u64,
    size: u64,
    section: Option<String>,
    source: &'static str,
}

/// Demangles Rust (legacy and v0) and C++ (Itanium) names. Mach-O adds a leading
/// underscore to every symbol, so both the name and the name without it are tried.
pub fn demangle(name: &str) -> Option<String> {
    let candidates = std::iter::once(name).chain(name.strip_prefix('_'));
    for n in candidates {
        if let Ok(d) = rustc_demangle::try_demangle(n) {
            return Some(format!("{d:#}"));
        }
        if n.starts_with("_Z")
            && let Some(d) = cpp_demangle::Symbol::new(n.as_bytes())
                .ok()
                .and_then(|sym| sym.demangle().ok())
        {
            return Some(d);
        }
    }
    None
}

pub struct SymbolsTable;

impl Table for SymbolsTable {
    type Item = Symbol;

    fn doc() -> &'static str {
        "Symbols from the symbol table and the dynamic symbol table."
    }

    fn columns() -> &'static [Column<Obj<Symbol>>] {
        static COLUMNS: &[Column<Obj<Symbol>>] = columns![
            Column {
                name: "name",
                ty: ColType::Varchar,
                doc: "Symbol name as stored (mangled).",
                get: |s| Cell::Str(s.name.clone()),
            },
            Column {
                name: "demangled",
                ty: ColType::Varchar,
                doc: "Demangled Rust or C++ name; NULL for other names. Only computed when selected.",
                get: |s| demangle(&s.name).into(),
            },
            Column {
                name: "kind",
                ty: ColType::Varchar,
                doc: "text, data, section, file, tls, label or unknown.",
                get: |s| Cell::Str(s.kind.clone()),
            },
            Column {
                name: "scope",
                ty: ColType::Varchar,
                doc: "compilation, linkage, dynamic or unknown.",
                get: |s| Cell::Str(s.scope.clone()),
            },
            Column {
                name: "defined",
                ty: ColType::Boolean,
                doc: "Defined in this object rather than imported.",
                get: |s| Cell::Bool(s.defined),
            },
            Column {
                name: "global",
                ty: ColType::Boolean,
                doc: "Global binding.",
                get: |s| Cell::Bool(s.global),
            },
            Column {
                name: "weak",
                ty: ColType::Boolean,
                doc: "Weak binding.",
                get: |s| Cell::Bool(s.weak),
            },
            Column {
                name: "address",
                ty: ColType::Ubigint,
                doc: "Address.",
                get: |s| Cell::UInt(s.address),
            },
            Column {
                name: "size",
                ty: ColType::Ubigint,
                doc: "Size in bytes.",
                get: |s| Cell::UInt(s.size),
            },
            Column {
                name: "section",
                ty: ColType::Varchar,
                doc: "Name of the section containing the symbol.",
                get: |s| s.section.clone().into(),
            },
            Column {
                name: "source",
                ty: ColType::Varchar,
                doc: "symtab or dynsym.",
                get: |s| str_cell(s.source),
            },
        ];
        COLUMNS
    }

    fn items(ctx: &Ctx, _: &Options) -> Result<Vec<Symbol>, BoxError> {
        let f = ctx.file;
        let convert = |sym: object::Symbol, source: &'static str| Symbol {
            name: sym.name_bytes().map(lossy).unwrap_or_default(),
            kind: debug_lower(sym.kind()),
            scope: debug_lower(sym.scope()),
            defined: sym.is_definition(),
            global: sym.is_global(),
            weak: sym.is_weak(),
            address: sym.address(),
            size: sym.size(),
            section: sym
                .section_index()
                .and_then(|i| f.section_by_index(i).ok())
                .and_then(|s| s.name_bytes().ok().map(lossy)),
            source,
        };
        Ok(f.symbols()
            .map(|s| convert(s, "symtab"))
            .chain(f.dynamic_symbols().map(|s| convert(s, "dynsym")))
            .filter(|s| !s.name.is_empty())
            .collect())
    }
}

// ---------------------------------------------------------------------------
// binary_imports: symbols this object needs from shared libraries
// ---------------------------------------------------------------------------

pub struct Import {
    library: Option<String>,
    name: String,
    version: Option<String>,
    weak: bool,
}

pub struct ImportsTable;

impl Table for ImportsTable {
    type Item = Import;

    fn doc() -> &'static str {
        "Symbols each object needs from shared libraries."
    }

    fn columns() -> &'static [Column<Obj<Import>>] {
        static COLUMNS: &[Column<Obj<Import>>] = columns![
            Column {
                name: "library",
                ty: ColType::Varchar,
                doc: "Library the symbol comes from. NULL for ELF unless the symbol version names a library, since ELF imports search every DT_NEEDED library.",
                get: |i| i.library.clone().into(),
            },
            Column {
                name: "name",
                ty: ColType::Varchar,
                doc: "Symbol name. PE imports by ordinal appear as #n.",
                get: |i| Cell::Str(i.name.clone()),
            },
            Column {
                name: "demangled",
                ty: ColType::Varchar,
                doc: "Demangled Rust or C++ name; NULL for other names.",
                get: |i| demangle(&i.name).into(),
            },
            Column {
                name: "version",
                ty: ColType::Varchar,
                doc: "ELF symbol version, such as GLIBC_2.2.5.",
                get: |i| i.version.clone().into(),
            },
            Column {
                name: "weak",
                ty: ColType::Boolean,
                doc: "Weak import: may be absent at run time.",
                get: |i| Cell::Bool(i.weak),
            },
        ];
        COLUMNS
    }

    fn items(ctx: &Ctx, _: &Options) -> Result<Vec<Import>, BoxError> {
        let mut out = Vec::new();
        for import in ctx.file.imports()? {
            let Ok(import) = import else { continue };
            out.push(Import {
                // ELF imports aren't bound to a library; the dynamic linker searches DT_NEEDED.
                library: Some(lossy(import.library())).filter(|l| !l.is_empty()),
                name: match import.name() {
                    NameOrOrdinal::Name(n) => lossy(n),
                    NameOrOrdinal::Ordinal(o) => format!("#{o}"),
                },
                version: match import.flags() {
                    ImportFlags::Elf { version, .. } => version.map(lossy),
                    _ => None,
                },
                weak: import.is_weak(),
            });
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// binary_libraries: the shared libraries this object depends on (ldd, without resolution)
// ---------------------------------------------------------------------------

pub struct Library {
    library: String,
    kind: &'static str,
    version: Option<String>,
}

fn macho_version(v: macho::Version) -> String {
    let v = v.0;
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

pub struct LibrariesTable;

impl Table for LibrariesTable {
    type Item = Library;

    fn doc() -> &'static str {
        "Shared libraries each object depends on, as written in the file (not resolved to paths), like ldd without the lookup."
    }

    fn columns() -> &'static [Column<Obj<Library>>] {
        static COLUMNS: &[Column<Obj<Library>>] = columns![
            Column {
                name: "library",
                ty: ColType::Varchar,
                doc: "Library name or install path as written in the file.",
                get: |l| Cell::Str(l.library.clone()),
            },
            Column {
                name: "kind",
                ty: ColType::Varchar,
                doc: "ELF: needed. Mach-O: load, weak, reexport, lazy or upward. PE: import or delay.",
                get: |l| str_cell(l.kind),
            },
            Column {
                name: "version",
                ty: ColType::Varchar,
                doc: "Mach-O current version; NULL for other formats.",
                get: |l| l.version.clone().into(),
            },
        ];
        COLUMNS
    }

    fn items(ctx: &Ctx, _: &Options) -> Result<Vec<Library>, BoxError> {
        let mut out = Vec::new();
        for lib in ctx.file.import_libraries()? {
            let Ok(lib) = lib else { continue };
            let (kind, version) = match lib.flags() {
                ImportLibraryFlags::MachO {
                    cmd,
                    current_version,
                    ..
                } => {
                    let kind = if cmd == macho::LC_LOAD_WEAK_DYLIB {
                        "weak"
                    } else if cmd == macho::LC_REEXPORT_DYLIB {
                        "reexport"
                    } else if cmd == macho::LC_LAZY_LOAD_DYLIB {
                        "lazy"
                    } else if cmd == macho::LC_LOAD_UPWARD_DYLIB {
                        "upward"
                    } else {
                        "load"
                    };
                    (kind, Some(macho_version(current_version)))
                }
                ImportLibraryFlags::Pe { delay: true } => ("delay", None),
                ImportLibraryFlags::Pe { delay: false } => ("import", None),
                _ => ("needed", None),
            };
            out.push(Library {
                library: lossy(lib.name()),
                kind,
                version,
            });
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// binary_strings: printable ASCII runs, like strings(1)
// ---------------------------------------------------------------------------

pub struct Str {
    offset: u64,
    value: String,
}

pub struct StringsTable;

impl Table for StringsTable {
    type Item = Str;

    fn doc() -> &'static str {
        "Printable ASCII runs, like strings(1). min_length sets the shortest run (default 4)."
    }

    fn columns() -> &'static [Column<Obj<Str>>] {
        static COLUMNS: &[Column<Obj<Str>>] = columns![
            Column {
                name: "offset",
                ty: ColType::Ubigint,
                doc: "Byte offset within the object.",
                get: |s| Cell::UInt(s.offset),
            },
            Column {
                name: "string",
                ty: ColType::Varchar,
                doc: "The printable run.",
                get: |s| Cell::Str(s.value.clone()),
            },
        ];
        COLUMNS
    }

    fn items(ctx: &Ctx, opts: &Options) -> Result<Vec<Str>, BoxError> {
        Ok(printable_runs(ctx.data, opts.min_length))
    }
}

pub fn printable_runs(data: &[u8], min_length: usize) -> Vec<Str> {
    let printable = |b: u8| b == b'\t' || (0x20..0x7f).contains(&b);
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in data.iter().chain(std::iter::once(&0)).enumerate() {
        match (printable(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                if i - s >= min_length {
                    out.push(Str {
                        offset: s as u64,
                        value: String::from_utf8_lossy(&data[s..i]).into_owned(),
                    });
                }
                start = None;
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_rust_cpp_and_macho_names() {
        assert_eq!(
            demangle("_ZN4core3fmt5write17h1234567890abcdefE").as_deref(),
            Some("core::fmt::write")
        );
        assert_eq!(demangle("_ZN3foo3barEv").as_deref(), Some("foo::bar()"));
        assert_eq!(demangle("__ZN3foo3barEv").as_deref(), Some("foo::bar()"));
        assert_eq!(demangle("main"), None);
        assert_eq!(demangle("_main"), None);
    }

    #[test]
    fn finds_printable_runs() {
        let runs = printable_runs(b"\x00\x01hello\x00hi\x00world!\xff", 4);
        let got: Vec<_> = runs.iter().map(|s| (s.offset, s.value.as_str())).collect();
        assert_eq!(got, vec![(2, "hello"), (11, "world!")]);
    }
}
