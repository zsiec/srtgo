#!/usr/bin/env bash
# Enforce the Sans-I/O purity invariant for the protocol core: no non-test
# source file under internal/core may directly import "net" or "time".
# The authoritative check is the AST-based TestNoForbiddenImports; this script
# is the CI-friendly entry point. See docs/sansio-migration.md.
set -euo pipefail
cd "$(dirname "$0")/.."
go test ./internal/core/ -run TestNoForbiddenImports -count=1
