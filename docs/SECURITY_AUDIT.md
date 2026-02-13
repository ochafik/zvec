# Security Audit Report: zvec

**Date**: 2026-02-13
**Scope**: Full codebase review (C++ core, Python bindings, dependencies, CI/CD)
**Branch**: `security/fixes`

---

## Executive Summary

zvec is an in-process vector database built on Alibaba's Proxima framework with a C++17 core and Python bindings via pybind11. This audit identified **5 code-level vulnerabilities** (mostly integer overflow in memory operations), **several outdated dependencies** with potential supply chain risk, and **missing security infrastructure** (no SECURITY.md, no fuzzing, no sanitizer CI).

All code-level findings have been fixed in this branch. Dependency updates and CI hardening are recommended as follow-up.

---

## Findings and Fixes

### 1. Integer Overflow in MMapFile Bounds Checks (MEDIUM-HIGH)

**File**: `src/include/zvec/ailego/io/mmap_file.h:163-226`
**Commit**: `fix(security): prevent integer overflow in MMapFile bounds checks`

**Problem**: All 6 read/write methods in `MMapFile` used `offset + len > region_size_` to check bounds. When `offset + len` exceeds `SIZE_MAX`, the addition wraps to a small value, the check passes, and `memcpy` writes/reads out of bounds.

**Fix**: Replaced with overflow-safe form: `len > region_size_ - offset` (after first checking `offset >= region_size_`).

**Impact**: Memory corruption via crafted file data or API misuse.

### 2. Pointer Overflow in MemoryWarmup (MEDIUM)

**File**: `src/ailego/io/file.cc:711-724`
**Commit**: `fix(security): prevent pointer overflow in MemoryWarmup`

**Problem**: `uint8_t *end = p + len` can wrap around when `len` is very large, causing the warmup loop to read arbitrary memory beyond the mapped region.

**Fix**: Added `uintptr_t` overflow check before computing the end pointer. Returns early if overflow would occur.

**Impact**: Out-of-bounds read; potential information disclosure or crash.

### 3. Integer Overflow in Flat Index Batch Operations (MEDIUM)

**File**: `src/core/algorithm/flat/flat_searcher_provider.h:38,84,184,200`
**Commit**: `fix(security): prevent integer overflow in flat index size calculations`

**Problem**: Multiple unchecked `BATCH_SIZE * feature_size_` and `index * feature_size_` multiplications using `uint32_t`. If `feature_size_` comes from corrupted index metadata, these can overflow, leading to undersized buffer allocations followed by buffer overflows.

**Fix**:
- Added `std::numeric_limits` overflow checks before `BATCH_SIZE * feature_size_` in constructors
- Cast to `uint64_t` before multiplication in offset calculations

**Impact**: Heap buffer overflow from malformed index files.

### 4. Unvalidated Buffer in Pickle Deserialization (MEDIUM)

**File**: `src/binding/python/model/python_doc.cc:66-73`
**Commit**: `fix(security): validate buffer before Doc deserialization in pickle`

**Problem**: `Doc::deserialize(buf, size)` was called without checking that `buf != nullptr` and `size > 0`. Malformed pickle data could trigger null pointer dereference or undefined behavior.

**Fix**: Added explicit null/size validation with a descriptive error message before deserialization.

**Impact**: Crash or undefined behavior from malformed pickle data.

### 5. SQL Parser Stack Overflow DoS (MEDIUM)

**File**: `src/db/sqlengine/parser/zvec_sql_parser.cc`
**Commit**: `fix(security): add query length limit to SQL parser to prevent DoS`

**Problem**: The ANTLR4 SQL parser had no depth or size limits. Deeply nested expressions like `(((((...(x)...)))))`  could cause unbounded recursion and stack overflow, crashing the process.

**Fix**: Added a 64KB query length limit to both `parse()` and `parse_filter()`. This bounds the maximum possible nesting depth proportionally.

**Impact**: Denial of service via crafted SQL queries.

### 6. Unsafe Process Termination (LOW)

**File**: `tools/core/convert_cohere_parquet.py:24,104,131`
**Commit**: `fix(security): replace os._exit() with sys.exit() for proper cleanup`

**Problem**: `os._exit(1)` bypasses all cleanup handlers (finally blocks, atexit, file flush). This can leave files in inconsistent state.

**Fix**: Replaced with `sys.exit(1)`.

**Impact**: Data corruption on error in utility script.

### 7. Missing Security Policy

**File**: `SECURITY.md` (new)
**Commit**: `docs(security): add SECURITY.md vulnerability reporting policy`

**Problem**: No vulnerability reporting process existed.

**Fix**: Added SECURITY.md with private reporting instructions, response timelines, and severity classification.

---

## Dependency Risk Assessment

All dependencies are pinned to specific git tags (good practice), but several are significantly outdated:

| Dependency | Version | Age | Risk | Action |
|---|---|---|---|---|
| **Protobuf** | 3.21.12 | ~2 years | HIGH | Upgrade to 3.25+ or 27.x |
| **RocksDB** | 8.1.1 | ~2 years | HIGH | Upgrade to 9.x |
| **Arrow** | 21.0.0 | ~2 years | MEDIUM | Evaluate 15.0+ |
| **yaml-cpp** | 0.6.3 | ~7 years | MEDIUM | Upgrade to 0.8.x |
| **glog** | 0.5.0 | ~4 years | LOW | Upgrade to 0.7.x |
| **ANTLR4** | 4.8 | ~6 years | LOW | Upgrade to 4.14.x |
| **LZ4** | 1.9.4 | minor | LOW | Upgrade to 1.10.x |
| **CRoaring** | 2.0.4 | ~1 year | LOW | Upgrade to 4.x |

### Recommended Actions
1. **Immediate**: Update Protobuf and RocksDB (highest supply chain risk)
2. **Short-term**: Update yaml-cpp, glog, Arrow
3. **Ongoing**: Set up Dependabot or OWASP Dependency-Check in CI

---

## Positive Security Practices

The following good practices were observed:

- **Pre-commit hooks**: gitleaks for secret detection, ruff for Python linting, clang-format for C++ formatting
- **API key handling**: Read from environment variables, never hardcoded
- **CI/CD**: GitHub Actions use pinned action versions (checkout@v4, setup-python@v5)
- **Compiler warnings**: `-Wall -Werror=return-type` enabled
- **File I/O**: EINTR retry loops, flock-based locking
- **Error propagation**: `tl::expected<T, Status>` pattern through pybind11 boundary
- **No dynamic code execution**: No `eval()`, `exec()`, or shell injection vectors
- **Input validation**: Strong type checking via pybind11 `checked_cast` pattern

---

## Recommendations for Further Hardening

### High Priority
1. **Enable AddressSanitizer (ASAN) in CI** for at least one build configuration to catch memory errors
2. **Add fuzz testing** for the SQL parser (`parse()`, `parse_filter()`) and Doc deserialization (`Doc::deserialize()`)
3. **Update critical dependencies** (Protobuf, RocksDB)

### Medium Priority
4. **Set up automated dependency monitoring** (Dependabot, Renovate, or OWASP Dependency-Check)
5. **Add MemorySanitizer (MSAN)** or **UndefinedBehaviorSanitizer (UBSAN)** CI job
6. **Audit `ReverseTranspose`** for divide-by-zero when `align_size == 0` in flat_searcher_provider.h

### Low Priority
7. **Replace `static_cast` with `dynamic_cast`** for ANTLR parse tree downcasts in doc_filter.cc
8. **Add resource limits** to Arrow query execution to prevent unbounded memory allocation
9. **Improve exception specificity** in Python extension error handlers (currently catching broad `Exception`)

---

## Files Modified

| File | Change |
|---|---|
| `src/include/zvec/ailego/io/mmap_file.h` | Overflow-safe bounds checks |
| `src/ailego/io/file.cc` | Pointer overflow guard in MemoryWarmup |
| `src/core/algorithm/flat/flat_searcher_provider.h` | Overflow checks for batch size calculations |
| `src/binding/python/model/python_doc.cc` | Buffer validation in pickle unpickle |
| `src/db/sqlengine/parser/zvec_sql_parser.cc` | Query length limit |
| `tools/core/convert_cohere_parquet.py` | Safe process exit |
| `SECURITY.md` | New vulnerability reporting policy |
| `docs/SECURITY_AUDIT.md` | This document |
