Botanj - Java Security Provider (JSP)
====================================

> ⚠️ **Caution:**  
> The code within this repository is currently in its early beta phase and has not been officially released.
> We would strongly advise against using it for production purposes until it reaches a stable, release-ready state.

[![ubuntu-build Actions Status](https://github.com/yaziza/botanj/workflows/ubuntu-build/badge.svg)](https://github.com/yaziza/botanj/actions?query=branch%3Amaster)

[![macos-build Actions Status](https://github.com/yaziza/botanj/workflows/macos-build/badge.svg)](https://github.com/yaziza/botanj/actions?query=branch%3Amaster)

[![codeql-analysis Actions Status](https://github.com/yaziza/botanj/workflows/codeql-analysis/badge.svg)](https://github.com/yaziza/botanj/actions?query=branch%3Amaster)

[![coverage](.github/badges/jacoco.svg)](https://github.com/yaziza/botanj/actions/workflows/code-coverage.yml)

[![branch coverage](.github/badges/branches.svg)](https://github.com/yaziza/botanj/actions/workflows/code-coverage.yml)

[![Known Vulnerabilities](https://snyk.io/test/github/yaziza/botanj/badge.svg)](https://snyk.io/test/github/yaziza/botanj)

## Index

1. [Introduction](#introduction)
2. [Documentation](#documentation)
3. [Building The Library](#building-the-library)
4. [Supported Primitives](#supported-primitives)
5. [Using Botan JSP](#using-botanj)

## Introduction
Botanj is a Java Security Provider ([JSP](https://docs.oracle.com/en/java/javase/14/security/java-cryptography-architecture-jca-reference-guide.html#GUID-3E0744CE-6AC7-4A6D-A1F6-6C01199E6920))
, which uses [Botan](https://botan.randombit.net/) to implements parts of the Java Cryptography Extension (JCE). This
implementation is compatible with other JSPs (e.g. Bouncy Castle), thus enabling a smooth migration.

Botanj uses [JNR-FFI](https://github.com/jnr/jnr-ffi) for loading Botan native code.

## Documentation
* [JavaDoc API Reference](https://yaziza.github.io/botanj/javadoc/)

Comprehensive API documentation with detailed usage examples, architecture explanations, and implementation notes for all cryptographic operations.

## Building The Library
* Install native [Botan](https://botan.randombit.net/handbook/building.html) Library
* Install Apache [Maven-3](https://maven.apache.org/)
* Install Java 17+ (tested with [openjdk 17/21/24](https://openjdk.java.net/))
* Run tests: (Botan library path macOS example)
`mvn test -Dnative.lib.path=/opt/homebrew/opt/botan/lib`

## Supported Primitives

### Ciphers, hashes, MACs, and checksums
* Authenticated cipher modes: EAX, OCB, GCM, SIV, CCM
* Cipher modes: CBC, CTR, CFB, OFB
* Block ciphers: AES, DES/3DES
* Stream ciphers: (X)Salsa20, (X)ChaCha20
* Hash functions: SHA-1, SHA-2, SHA-3, MD4, MD5, RIPEMD-160, BLAKE2b
* Message Authentication codes: HMAC, CMAC, Poly1305, SipHash

### Public Key Cryptography
* Not yet supported

### Public Key Infrastructure
* Not yes supported

### Transport Layer Security (TLS) Protocol (JSSE)
* Not yet supported

## Using Botanj
* An example describing the procedure to compute a MessageDigest object:

```java
final MessageDigest digest = MessageDigest.getInstance("blake2b-512", BotanProvider.NAME);
final byte[] output = digest.digest("hello world".getBytes());
```

* An example describing the procedure to compute a MAC object:

```java
final SecretKeySpec key = new SecretKeySpec(key, "HMAC-SHA512");
final Mac mac = Mac.getInstance("HMAC-SHA512", BotanProvider.NAME);
mac.init(key);
final byte[] output = mac.doFinal("hello world".getBytes());
```

* An example describing the procedure to encrypt using AES-256/GCM:

```java
final Cipher cipher = Cipher.getInstance("AES-256/GCM/NoPadding", BotanProvider.NAME);
// Never reuse the IV with the same key
cipher.init(Cipher.ENCRYPT_MODE, key, iv);
cipher.updateAAD(aad);
final byte[] output = cipher.doFinal("hello world".getBytes());
```

* An example describing the procedure to encrypt using AES-256/CBC/PKCS7:
```java
final Cipher cipher = Cipher.getInstance("AES-256/CBC/PKCS7", BotanProvider.NAME);
cipher.init(Cipher.ENCRYPT_MODE, key, iv);
final byte[] output = cipher.doFinal("hello world".getBytes());
```

* An example describing the procedure to encrypt using ChaCha20:
```java
final Cipher cipher = Cipher.getInstance("ChaCha20/None/NoPadding", BotanProvider.NAME);
// Never reuse the IV with the same key
cipher.init(Cipher.ENCRYPT_MODE, key, iv);
final byte[] output = cipher.doFinal("hello world".getBytes());
```
