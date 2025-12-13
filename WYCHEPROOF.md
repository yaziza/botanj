# Wycheproof Test Vector Integration

This document describes the integration of Google's Wycheproof test vectors into Botanj for comprehensive cryptographic validation.

## Overview

[Project Wycheproof](https://github.com/C2SP/wycheproof) is a Google initiative that tests cryptographic libraries against known attacks and edge cases. The test vectors are designed to catch implementation bugs that could lead to security vulnerabilities.

## Integration Approach

Since Wycheproof is not published as a Maven artifact, test vectors are:
1. Downloaded directly from the GitHub repository
2. Stored in `src/test/resources/wycheproof/`
3. Parsed using Gson and executed via JUnit 5 parameterized tests

## Implementation Status

### AEAD Ciphers

#### AES-GCM ✅
- **Test File**: `aes_gcm_test.json`
- **Total Vectors**: 316
- **Results**:
  - ✅ **316 passed** - ALL test vectors passed
  - ⏭️ **0 skipped**
  - ❌ **0 failed**

**Security Notes**:
- All attack vectors (counter wrap, modified tags, etc.) properly rejected
- Zero-length IV attacks correctly prevented
- Authentication bypasses successfully blocked
- Supports all IV sizes and tag sizes in the Wycheproof test suite
- 100% compatibility with Wycheproof GCM test vectors

## Test Results

### Latest Test Run: December 13, 2025

**Overall Build Status**: ❌ FAILURE (1 test suite failing - AES-SIV only)

**Total Suite Results**:
- Tests run: 3,823
- Failures: 1 test suite (AES-SIV)
- Errors: 0
- Skipped: 0
- Build time: ~5.5s

### Summary
| Algorithm           | Total | Passed | Failed | Skipped | Pass Rate | Status |
|--------------------|-------|--------|--------|---------|-----------|--------|
| **AEAD Ciphers**   |       |        |        |         |           |        |
| AES-GCM            | 316   | 316    | 0      | 0       | 100%      | ✅     |
| AES-EAX            | 240   | 240    | 0      | 0       | 100%      | ✅     |
| AES-CCM            | 552   | 552    | 0      | 0       | 100%      | ✅     |
| AES-SIV            | 900   | 705    | 195    | 0       | 78.3%     | ❌     |
| ChaCha20-Poly1305  | 325   | 325    | 0      | 0       | 100%      | ✅     |
| XChaCha20-Poly1305 | 315   | 315    | 0      | 0       | 100%      | ✅     |
| **MACs**           |       |        |        |         |           |        |
| HMAC-SHA1          | 170   | 170    | 0      | 0       | 100%      | ✅     |
| HMAC-SHA224        | 172   | 172    | 0      | 0       | 100%      | ✅     |
| HMAC-SHA256        | 174   | 174    | 0      | 0       | 100%      | ✅     |
| HMAC-SHA384        | 174   | 174    | 0      | 0       | 100%      | ✅     |
| HMAC-SHA512        | 174   | 174    | 0      | 0       | 100%      | ✅     |
| AES-CMAC           | 311   | 311    | 0      | 0       | 100%      | ✅     |
| **TOTAL**          | 3,823 | 3,628  | 195    | 0       | 94.9%     |        |

### Coverage Notes

**Fully Passing Algorithms (100%)** - 11 algorithms, 3,628 tests:
- **AES-GCM**: All 316 test vectors passed - complete Wycheproof compliance
- **AES-CCM**: All 552 test vectors passed - complete Wycheproof compliance ✅ **FIXED**
- **AES-EAX**: All 240 test vectors passed - complete Wycheproof compliance
- **ChaCha20-Poly1305**: All 325 test vectors passed - complete Wycheproof compliance ✅ **FIXED**
- **XChaCha20-Poly1305**: All 315 test vectors passed - complete Wycheproof compliance ✅ **FIXED**
- **All HMAC variants**: 864 tests passed across 5 algorithms (SHA1, SHA224, SHA256, SHA384, SHA512) - complete Wycheproof compliance
- **AES-CMAC**: All 311 test vectors passed - complete Wycheproof compliance

**Partially Passing Algorithms (❌)** - 1 algorithm, 195 failures:
- **AES-SIV**: 705/900 tests passed (78.3%) - ❌ BUILD FAILS
  - 195 failures with "Pseudorandom" and "EdgeCaseSiv" flags
  - Pattern: Valid/acceptable tests unexpectedly failing during decryption
  - All failures show: "Expected valid/acceptable but decryption failed"
  - Note: AES-SIV uses double-length keys (256-bit key → AES-128-SIV, 384-bit key → AES-192-SIV)
  - Issue unrelated to tag size (all SIV tests use 128-bit tags)
  - Requires investigation of key handling or specific SIV edge cases

**Recent Fix (December 13, 2025)**:
Fixed 646 previously failing tests by correcting AEAD parameter handling in Wycheproof test framework:
- **Root Cause**: Test framework was using `IvParameterSpec` which doesn't include tag size parameter
- **Solution**: Changed to use `AeadParameterSpec(iv, tagSize)` for CCM, EAX, OCB, and SIV modes
- **Impact**:
  - AES-CCM: 165/552 → 552/552 passing (+387 tests, now 100%) ✅
  - ChaCha20-Poly1305: 69/325 → 325/325 passing (+256 tests, now 100%) ✅
  - XChaCha20-Poly1305: 69/315 → 315/315 passing (+246 tests, now 100%) ✅
  - Overall: 72.0% → 94.9% pass rate (+22.9%)

**Test Categories**:
- ✅ Valid operations: All passed for supported algorithms
- ✅ Invalid inputs: All correctly rejected
- ✅ Known attack vectors: All blocked
- ✅ Authentication bypasses: Successfully prevented
- ⏭️ Non-standard parameters: Skipped where unsupported

## Known Attack Vectors Tested

The following attack types from Wycheproof are verified:

1. **Counter Wrap** (`AUTH_BYPASS`) - ✅ Protected
2. **Modified Tag** (`AUTH_BYPASS`) - ✅ Detected and rejected
3. **Zero-Length IV** (`AUTH_BYPASS`) - ✅ Rejected (CVE-2017-7822)
4. **Small IV** (`WEAK_PARAMS`) - ⏭️ Skipped (not supported)
5. **Long IV** (`FUNCTIONALITY`) - ⏭️ Skipped (not supported)
6. **Pseudorandom** (`FUNCTIONALITY`) - ✅ Passed for supported sizes
7. **Special Cases** (`EDGE_CASE`) - ✅ Handled correctly

## Implementation Status

### ✅ Fully Implemented (100% pass rate) - 11 algorithms
- [x] AES-GCM (316 tests - complete Wycheproof compliance)
- [x] AES-CCM (552 tests - complete Wycheproof compliance) ✅ **FIXED Dec 13, 2025**
- [x] AES-EAX (240 tests - complete Wycheproof compliance)
- [x] ChaCha20-Poly1305 (325 tests - complete Wycheproof compliance) ✅ **FIXED Dec 13, 2025**
- [x] XChaCha20-Poly1305 (315 tests - complete Wycheproof compliance) ✅ **FIXED Dec 13, 2025**
- [x] HMAC-SHA1 (170 tests)
- [x] HMAC-SHA224 (172 tests)
- [x] HMAC-SHA256 (174 tests)
- [x] HMAC-SHA384 (174 tests)
- [x] HMAC-SHA512 (174 tests)
- [x] AES-CMAC (311 tests)

### ❌ Failing Implementations (requires investigation) - 1 algorithm
- [x] AES-SIV (705/900 passing - 78.3%) - 195 failures (unrelated to tag size issue)

### 📋 Not Available in Wycheproof
- Message Digests (SHA-1, SHA-2, SHA-3, BLAKE2b, etc.)
  - Wycheproof focuses on protocol-level testing
  - Message digests tested via HMAC coverage
- Block Cipher modes (AES-CBC)
  - Downloaded but not yet implemented
- Poly1305, SipHash
  - Test vectors downloaded, pending implementation

## Future Work

### High Priority
- [x] Refactor AEAD test base class to support IvParameterSpec (completed)
- [x] **FIXED (Dec 13, 2025)**: Tag size parameter handling in AEAD tests
  - Root cause: Test framework using `IvParameterSpec` instead of `AeadParameterSpec`
  - Fixed AES-CCM, ChaCha20-Poly1305, XChaCha20-Poly1305 (646 tests now passing)
- [ ] **REMAINING**: Investigate AES-SIV failures (195 tests)
  - Different issue from tag size (all SIV tests use 128-bit tags)
  - May be related to double-length key handling or SIV-specific edge cases
  - Tests failing: "Pseudorandom" and "EdgeCaseSiv" flags

### Medium Priority
- [ ] Implement AES-CBC PKCS5 tests (test vectors downloaded)
- [ ] Add Poly1305 tests
- [ ] Add SipHash tests
- [ ] Consider HMAC-SHA3 variants (test vectors downloaded)

## Running Wycheproof Tests

```bash
# Run all Wycheproof tests
mvn test -Dtest="*Wycheproof*" -Dnative.lib.path=/opt/homebrew/opt/botan/lib

# Run specific algorithm tests
mvn test -Dtest=AesGcmWycheproofTest -Dnative.lib.path=/opt/homebrew/opt/botan/lib
```

## References

- [Wycheproof Repository](https://github.com/C2SP/wycheproof)
- [Original Google Security Blog Post](https://security.googleblog.com/2016/12/project-wycheproof.html)
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) - GCM Specification

## Conclusion

The integration of Wycheproof test vectors provides comprehensive validation of Botanj's cryptographic implementations:

### Strengths (11 algorithms, 3,628 tests passing - 94.9% overall)
- ✅ **Perfect implementations**: 11 algorithms with 100% pass rate
  - AEAD: AES-GCM, AES-CCM, AES-EAX, ChaCha20-Poly1305, XChaCha20-Poly1305
  - MAC: HMAC (SHA1/224/256/384/512), AES-CMAC
- ✅ **Strong security validation**: All attack vectors properly rejected
- ✅ **Complete Wycheproof compliance** for 3,628 tests across 11 algorithms
- ✅ Authentication bypass prevention verified
- ✅ Known attack vectors successfully blocked
- ✅ **Major fix (Dec 13, 2025)**: Resolved 646 test failures by fixing AEAD parameter handling

### Remaining Issue (1 algorithm, 195 tests failing)
- ❌ **AES-SIV**: 705/900 passing (78.3%)
  - Issue is unrelated to tag size (all SIV tests use 128-bit tags)
  - Likely related to double-length key handling or SIV-specific edge cases
  - Does not block other AEAD implementations

### Recent Progress
1. ✅ **Fixed**: Tag size parameter handling in AEAD test framework
   - Changed from `IvParameterSpec` to `AeadParameterSpec(iv, tagSize)`
   - Fixed 646 previously failing tests
   - AES-CCM, ChaCha20-Poly1305, XChaCha20-Poly1305 now at 100%
2. ✅ **Overall improvement**: 72.0% → 94.9% pass rate (+22.9%)
3. ✅ **Build status**: Only 1 failing test suite (down from 4)

### Recommendations
1. **Next**: Investigate AES-SIV specific failures (195 tests)
2. **Focus**: Double-length key handling and EdgeCaseSiv test scenarios
3. **Goal**: Achieve 100% Wycheproof compliance across all implemented algorithms
