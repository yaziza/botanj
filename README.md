Botanj - Java Security Provider (JSP)
====================================

[![Build Status](https://travis-ci.com/yaziza/botanj.svg?token=MyNJQboScT4FWA4jhyVU&branch=master)](https://travis-ci.com/yaziza/botanj)

## Index

1. [Introduction](#introduction)
2. [Building The Library](#building-the-library)
3. [Using Botan JSP](#using-botanj)
4. [Supported Primitives](#supported-primitives)

## Introduction
Botanj is a Java Security Provider ([JSP](https://docs.oracle.com/en/java/javase/14/security/java-cryptography-architecture-jca-reference-guide.html#GUID-3E0744CE-6AC7-4A6D-A1F6-6C01199E6920))
, which uses [Botan](https://botan.randombit.net/) to implements parts of the Java Cryptography Extension (JCE). This
implementation is compatible with other JSPs (e.g. Bouncy Castle), thus enabling a smooth migration.

Botanj uses [JNR-FFI](https://github.com/jnr/jnr-ffi) for loading Botan native code.

## Building The Library
* Install native [Botan](https://botan.randombit.net/handbook/building.html) Library under `src/main/resources/native`
* Install Apache [Maven](https://maven.apache.org/)
* Install Java 11+ (tested with [openjdk 11](https://openjdk.java.net/))
* Run tests against Bouncy castle Provider:
`mvn test`

## Using Botanj
An example describing the procedure to compute a MessageDigest object:

```java
final MessageDigest digest = MessageDigest.getInstance("blake2b-512", BotanProvider.NAME);
final byte[] output = digest.digest("hello world".getBytes());
```

An example describing the procedure to compute a MAC object:

```java
final SecretKeySpec key = new SecretKeySpec(key, "HMAC-SHA512");
final Mac mac = Mac.getInstance("HMAC-SHA512", BotanProvider.NAME);
mac.init(key);
final byte[] output = mac.doFinal("hello world".getBytes());
```

An example describing the procedure to encrypt using AES-256/GCM:
```java
final Cipher cipher = Cipher.getInstance("AES-256/GCM/NoPadding", BotanProvider.NAME);
cipher.init(Cipher.ENCRYPT_MODE, key, iv);
cipher.updateAAD(aad);
final byte[] output = cipher.doFinal("hello world".getBytes());
```

An example describing the procedure to encrypt using AES-256/CBC/PKCS7:
```java
final Cipher cipher = Cipher.getInstance("AES-256/CBC/PKCS7", BotanProvider.NAME);
cipher.init(Cipher.ENCRYPT_MODE, key, iv);
final byte[] output = cipher.doFinal("hello world".getBytes());
```

## Supported Primitives

### Ciphers, hashes, MACs, and checksums
* Authenticated cipher modes: GCM
* Cipher modes: CBC, CTR, CFB, OFB
* Block ciphers: AES, DES/3DES
* Stream ciphers: Not yet supported
* Hash functions: SHA-1, SHA-2, SHA-3, MD4, MD5, RIPEMD-160, BLAKE2b
* Message Authentication codes: HMAC

### Public Key Cryptography
* Not yet supported

### Transport Layer Security (TLS) Protocol (JSSE)
* Not yet supported

### Public Key Infrastructure
* Not yes supported
