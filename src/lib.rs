//! `binaries`: query ELF, Mach-O and PE files from DuckDB. Read-only.
//!
//!   SELECT * FROM binary_info('/usr/bin/*');
//!   SELECT path, library FROM binary_libraries('/usr/lib/**/*.so*');
//!   SELECT demangled FROM binary_symbols('target/release/app') WHERE defined;
//!   SELECT * FROM binary_describe();

mod scan;
mod tables;

use duckdb_tables::{Bind, BoxError, ColType, Column, Extension, Param, ScanTable};
use std::{marker::PhantomData, path::PathBuf, sync::Arc};
use tables::{Obj, Options, Table};

pub struct Args {
    pattern: String,
    min_length: usize,
    /// With a glob, files that can't be parsed are skipped; a single path must parse.
    strict: bool,
}

/// Every `Table` is scanned the same way: one unit per file, in parallel batches.
struct Binary<T>(PhantomData<T>);

impl<T: Table> ScanTable for Binary<T> {
    type Item = Obj<T::Item>;
    type Unit = PathBuf;
    type Args = Args;

    fn doc() -> &'static str {
        T::doc()
    }

    fn columns() -> &'static [Column<Obj<T::Item>>] {
        T::columns()
    }

    fn positional() -> &'static [Param] {
        &[Param {
            name: "path",
            ty: ColType::Varchar,
            doc: "A file, or a glob (*, ?, [...], {a,b}, and ** for recursive). With a glob, files that aren't ELF, Mach-O or PE are skipped.",
        }]
    }

    fn named() -> &'static [Param] {
        &[Param {
            name: "min_length",
            ty: ColType::Bigint,
            doc: "binary_strings only: the shortest run to report. Default 4.",
        }]
    }

    fn bind(bind: &Bind) -> Result<Args, BoxError> {
        let min_length = bind.named_i64("min_length").unwrap_or(4);
        if min_length < 1 {
            return Err("min_length must be at least 1".into());
        }
        let pattern = bind.positional(0).to_string();
        Ok(Args {
            strict: !scan::is_glob(&pattern),
            pattern,
            min_length: min_length as usize,
        })
    }

    fn units(args: &Args) -> Result<Vec<PathBuf>, BoxError> {
        scan::expand(&args.pattern)
    }

    fn scan(path: &PathBuf, args: &Args, emit: &mut dyn FnMut(&Obj<T::Item>)) -> Result<(), BoxError> {
        let opts = Options {
            min_length: args.min_length,
        };
        scan::for_each_object(path, |ctx| {
            let (path, arch): (Arc<str>, Arc<str>) = (ctx.path.into(), ctx.arch.as_str().into());
            for item in T::items(ctx, &opts)? {
                emit(&Obj {
                    path: path.clone(),
                    arch: arch.clone(),
                    item,
                });
            }
            Ok(())
        })
    }

    fn skip_errors(args: &Args) -> bool {
        !args.strict
    }
}

duckdb_tables::entrypoint!(binaries_init_c_api, init);

fn init(ext: &Extension) -> Result<(), BoxError> {
    ext.register_describe("binary_describe")?;
    ext.register_scan::<Binary<tables::InfoTable>>("binary_info")?;
    ext.register_scan::<Binary<tables::SectionsTable>>("binary_sections")?;
    ext.register_scan::<Binary<tables::SegmentsTable>>("binary_segments")?;
    ext.register_scan::<Binary<tables::SymbolsTable>>("binary_symbols")?;
    ext.register_scan::<Binary<tables::ImportsTable>>("binary_imports")?;
    ext.register_scan::<Binary<tables::LibrariesTable>>("binary_libraries")?;
    ext.register_scan::<Binary<tables::StringsTable>>("binary_strings")?;
    Ok(())
}
