Botanj - Java Security Provider (JSP)
====================================

[![Build Status](https://travis-ci.com/yaziza/botanj.svg?token=MyNJQboScT4FWA4jhyVU&branch=master)](https://travis-ci.com/yaziza/botanj)

## Index

1. [Introduction](#introduction)
2. [Building The Library](#building-the-library)
3. [Using Botan JSP](#using-botan-jsp)
4. [Supported Primitives](#supported-primitives)

## Introduction
Botanj is a Java Security Provider ([JSP](https://docs.oracle.com/en/java/javase/14/security/java-cryptography-architecture-jca-reference-guide.html#GUID-3E0744CE-6AC7-4A6D-A1F6-6C01199E6920))
, which uses [Botan](https://botan.randombit.net/) to implements parts of the Java Cryptography Extension (JCE). This
implementation is compatible with other JSPs (e.g. Bouncy Castle), thus enabling a smooth migration.

Botanj uses [JNR-FFI](https://github.com/jnr/jnr-ffi) for loading Botan native code.

## Building The Library
* [Install](https://botan.randombit.net/handbook/building.html) native Botan Library under `src/main/resources/native`
* [Install](https://maven.apache.org/) Maven
* [Install](https://openjdk.java.net/) Java 1.8+ (tested with openjdk8 / 11)
* Run tests against Bouncy castle Provider:
`mvn test`

## Using Botanj JSP
An example describing the procedure to compute a MessageDigest object:

```java
final MessageDigest digest = MessageDigest.getInstance("blake2b-384", BotanProvider.PROVIDER_NAME);
final byte[] output = digest.digest("hello world".getBytes());
```

An example describing the procedure to compute a MAC object:

```java
final SecretKeySpec key = new SecretKeySpec(key, "HMAC-SHA512");
final Mac mac = Mac.getInstance("HMAC-384", BotanProvider.PROVIDER_NAME);
mac.init(key);
final byte[] output = mac.doFinal("hello world".getBytes());
```

## Supported Primitives

### Ciphers, hashes, MACs, and checksums
* Hash functions: SHA-1, SHA-2, SHA-3, MD4, MD5, RIPEMD-160, BLAKE2b
* Message Authentication codes: HMAC
* Block ciphers: AES(WIP)

### Public Key Cryptography
* Not yet supported

### Transport Layer Security (TLS) Protocol (JSSE)
* Not yet supported

### Public Key Infrastructure
* Not yes supported
