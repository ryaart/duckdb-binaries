.PHONY: clean clean_all fixtures integration

PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

EXTENSION_NAME=binaries

# Set to 1 to enable Unstable API (binaries will only work on TARGET_DUCKDB_VERSION, forwards compatibility will be broken)
# Note: currently extension-template-rs requires this, as duckdb-rs relies on unstable C API functionality
USE_UNSTABLE_C_API=1

# Target DuckDB version
TARGET_DUCKDB_VERSION=v1.5.6

all: configure debug

# Include makefiles from DuckDB
include extension-ci-tools/makefiles/c_api_extensions/base.Makefile
include extension-ci-tools/makefiles/c_api_extensions/rust.Makefile

configure: venv platform extension_version

debug: build_extension_library_debug build_extension_with_metadata_debug
release: build_extension_library_release build_extension_with_metadata_release

# The SQL tests read test/fixtures/, which is downloaded rather than committed.
test: test_debug
test_debug: fixtures test_extension_debug
test_release: fixtures test_extension_release

fixtures:
	scripts/fixtures.sh

clean: clean_build clean_rust
clean_all: clean_configure clean

integration: debug test_debug
