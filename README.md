# binaries: SQL over executables and libraries

A read-only DuckDB extension that reads ELF, Mach-O (including universal binaries) and PE files as tables.
It's inspired by [sqlelf](https://github.com/fzakaria/sqlelf) and the ["your executable is a database"](https://fzakaria.com/2026/08/23/your-executable-is-a-sqlite-database) idea,
but works on the binaries you already have, on any OS, and uses DuckDB to scan whole directory trees in parallel.

```sql
LOAD binaries;

-- ldd for every binary on the system (unresolved: what each one asks for)
SELECT library, count(DISTINCT path) AS users
FROM binary_libraries('/usr/bin/*') GROUP BY 1 ORDER BY 2 DESC;

-- which binaries call into OpenSSL?
SELECT DISTINCT path FROM binary_imports('/usr/lib/**/*.so*') WHERE name LIKE 'SSL_%';

-- largest functions in a Rust build, demangled
SELECT demangled, size FROM binary_symbols('target/release/app')
WHERE kind = 'text' AND defined ORDER BY size DESC LIMIT 20;

-- strip candidates: binaries shipping debug info
SELECT path, size FROM binary_info('/opt/app/**/*') WHERE has_debug_info;
```

## Functions

Call `binary_describe()` for every function, parameter and column, with descriptions.

Every function takes a path or a glob (`*`, `?`, `[...]`, `{a,b}`, and `**` for recursive), and returns `path` and `arch` as its first columns.
- A universal Mach-O gives one set of rows per architecture.
- With a glob, files that aren't ELF, Mach-O or PE are skipped. A single path that isn't one is an error.
- Files are parsed in parallel batches and streamed, so large trees don't need to fit in memory.
- Only the columns a query uses are computed. For example, `demangled` costs nothing unless it's selected.

| function | columns (after `path, arch`) |
|---|---|
| `binary_info(p)` | `format` (elf/macho/pe/coff), `kind` (executable/dynamic/relocatable/core), `bits, endian, entry, build_id, interpreter, soname, rpath, runpath, has_symbols, has_debug_info, size, file_size` |
| `binary_sections(p)` | `name, segment, kind, address, size, file_offset, file_size, align` |
| `binary_segments(p)` | `name, address, size, file_offset, file_size, r, w, x` |
| `binary_symbols(p)` | `name, demangled, kind, scope, defined, global, weak, address, size, section, source` (`symtab` or `dynsym`) |
| `binary_imports(p)` | `library, name, demangled, version, weak`: the symbols the binary needs from shared libraries |
| `binary_libraries(p)` | `library, kind, version`: the libraries the binary depends on, not resolved to paths |
| `binary_strings(p, min_length := 4)` | `offset, string`: printable ASCII runs, like `strings(1)` |

How the formats map onto the columns:
- **Libraries:** `kind` is `needed` for ELF `DT_NEEDED` entries. For Mach-O it's `load`, `weak`, `reexport`, `lazy` or `upward`, and `version` is the dylib's current version. For PE it's `import` or `delay`.
- **`binary_info`:**
  - `soname` is the Mach-O install name.
  - `rpath` joins Mach-O `LC_RPATH` entries with `:`.
  - `interpreter` is `PT_INTERP` on ELF and the dylinker on Mach-O.
  - `build_id` is the ELF GNU build ID in hex, or the Mach-O UUID.
  - PIE executables are reported as `executable`, as `file(1)` does.
- **Imports:** ELF imports have no library of their own, since the dynamic linker searches all `DT_NEEDED` libraries. `library` is filled in when the symbol's version (e.g. `GLIBC_2.2.5`) names one. PE imports by ordinal appear as `#n`.
- **Demangling:** covers Rust (legacy and v0) and C++ (Itanium), including Mach-O's extra leading underscore. Other names are NULL.

## Design notes

- **Read-only.** Nothing writes to files, so it's safe to hand to agents.
- **Built on [`duckdb-tables`](../duckdb-tables),** shared with `os` and `k8s`. Each table declares its columns as (name, type, description, getter), and the crate handles the parallel batches, projection and `binary_describe()`.
- **Rust on DuckDB's C extension API.** Parsing uses gimli's [`object`](https://crates.io/crates/object) crate, the same one used by the Rust toolchain.
- **Pinned to one DuckDB version.** duckdb-rs uses the unstable C API (`TARGET_DUCKDB_VERSION` in the Makefile).
- **Not yet supported:** static archives (`.a`), the macOS dyld shared cache (where most system dylibs actually live), relocations, disassembly and DWARF.

## Development

```sh
git clone --recurse-submodules <repo>   # fetches duckdb-tables from GitHub
make configure
make debug          # build/debug/binaries.duckdb_extension
make integration    # downloads fixtures (scripts/fixtures.sh), runs test/sql
cargo test          # unit tests: demangling, strings
```

Fixtures come from [gimli-rs/object-testfiles](https://github.com/gimli-rs/object-testfiles), pinned to a commit. They're downloaded rather than committed, because that repo has no license file.
`scripts/make_fat.py` builds the universal Mach-O fixture from two thin ones, so the tests don't need `lipo`.
