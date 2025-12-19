# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Botanj is a Java Security Provider (JSP) that implements parts of the Java Cryptography Extension (JCE) using the native Botan cryptography library. 

## Build and Test Commands

### Common Commands
```bash
# Run all tests with custom Botan library path (macOS example)
mvn test -Dnative.lib.path=/opt/homebrew/opt/botan/lib

# Run single test class
mvn test -Dtest=BotanMessageDigestTest -Dnative.lib.path=/opt/homebrew/opt/botan/lib

# Run single test method
mvn test -Dtest=BotanMessageDigestTest#testSha256 -Dnative.lib.path=/opt/homebrew/opt/botan/lib

# Run checkstyle
mvn --update-snapshots clean verify -Dnative.lib.path=/opt/homebrew/opt/botan/lib

# Generate code coverage report
mvn jacoco:report
```

## Architecture

### Native Library Integration
- **BotanLibrary** (src/main/java/net/randombit/botan/jnr/BotanLibrary.java): JNR-FFI interface defining all native Botan functions
- **BotanInstance** (src/main/java/net/randombit/botan/jnr/BotanInstance.java): Singleton loader for the native library with lazy initialization and error handling

### Provider Registration
**BotanProvider** (src/main/java/net/randombit/botan/BotanProvider.java) is the main entry point that:
- Extends `java.security.Provider`
- Registers all supported cryptographic algorithms during initialization
- Maps JCE algorithm names to implementation classes

### Cipher Architecture
Ciphers are organized into different categories:

1. **Block Ciphers** (src/main/java/net/randombit/botan/seckey/block/)
   - Modes: CBC, CFB
   - Support multiple padding schemes (PKCS7, PKCS5, OneAndZeros, X9.23, ESP, NoPadding)
   - Examples: AES/CBC, DES/CBC, DESede/CBC

2. **Stream Ciphers** (src/main/java/net/randombit/botan/seckey/stream/)
   - Modes: CTR, OFB for block ciphers; dedicated stream ciphers
   - No padding (stream mode)
   - Examples: AES/CTR, ChaCha20, Salsa20

3. **AEAD Ciphers** (src/main/java/net/randombit/botan/seckey/block/aead/)
   - Authenticated encryption modes
   - No padding required
   - Examples: AES/GCM, AES/CCM, AES/EAX, AES/OCB, AES/SIV

**CipherMode** enum (src/main/java/net/randombit/botan/seckey/CipherMode.java) defines supported modes and their compatible padding algorithms.

### Other Cryptographic Services
- **MessageDigest** (src/main/java/net/randombit/botan/digest/): Hash functions (SHA-1, SHA-2, SHA-3, MD4/5, BLAKE2b, Keccak, RIPEMD-160)
- **Mac** (src/main/java/net/randombit/botan/mac/): Message authentication codes (HMAC, CMAC, Poly1305, SipHash)

### Test Structure
- Test vectors located in src/test/resources/ organized by algorithm type (digest/, mac/, seckey/)
- Tests use JUnit 5 with parameterized tests
- Bouncy Castle used as reference implementation for compatibility testing

## Important Notes

### Cipher Transformation Format
JCE transformations follow the pattern: `Algorithm/Mode/Padding`
- Block cipher modes (CBC, CFB): Support padding variations
- Stream modes (CTR, OFB, stream ciphers): Use `/None/NoPadding` or `/NoPadding`
- AEAD modes (GCM, CCM, etc.): Always use `/NoPadding`

### Error Handling
- Native errors are checked via `BotanInstance.checkNativeCall()`
- Returns Botan error descriptions for debugging
- Initial library load errors stored in `loadError` to avoid repeated exceptions
