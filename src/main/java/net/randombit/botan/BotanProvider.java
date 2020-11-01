/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan;

import java.security.Provider;

import net.randombit.botan.jnr.BotanInstance;
import net.randombit.botan.jnr.BotanLibrary;

public final class BotanProvider extends Provider {

    public static final String NAME = "Botan";
    private static final String INFO = "Botan Java Security Provider";

    private static final String PACKAGE_NAME = BotanProvider.class.getPackage().getName();
    private static final String DIGEST_PREFIX = ".digest.";
    private static final String MAC_PREFIX = ".mac.";
    private static final String BLOCK_CIPHER_PREFIX = ".seckey.block.";
    private static final String STREAM_CIPHER_PREFIX = ".seckey.stream.";
    private static final String AEAD_CIPHER_PREFIX = ".seckey.aead.";

    private static final BotanLibrary NATIVE = BotanInstance.singleton();

    public BotanProvider() {
        super(NAME, "", INFO);

        BotanInstance.checkAvailability();

        // Message Digests
        addMdAlgorithm();
        addSha1Algorithm();
        addSha2Algorithm();
        addSha3Algorithm();
        addKeccakAlgorithm();
        addBlake2Algorithm();

        // Message Authentication Codes
        addHmacAlgorithm();
        addCmacAlgorithm();
        addPoly1305Algorithm();
        addSipHashAlgorithm();

        // Block Ciphers
        addAesAlgorithm();
        addDesAlgorithm();
        addTrippleDesAlgorithm();

        // Stream Ciphers
        addSalsa20Algorithm();
        addChaCha20Algorithm();
    }

    @Override
    public String getInfo() {
        return INFO;
    }

    @Override
    public String getVersionStr() {
        return NATIVE.botan_version_string();
    }

    @Override
    public String toString() {
        return INFO + " version: " + NATIVE.botan_version_string();
    }

    private void addMdAlgorithm() {
        put("MessageDigest.MD4", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$MD4");
        put("Alg.Alias.MessageDigest.1.3.6.1.4.1.37476.3.2.1.99.1", "MD4");

        put("MessageDigest.MD5", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$MD5");
        put("Alg.Alias.MessageDigest.1.2.840.113549.2.5", "MD5");

        put("MessageDigest.RIPEMD-160", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$RipeMd160");
        put("Alg.Alias.MessageDigest.RIPEMD160", "RIPEMD-160");
        put("Alg.Alias.MessageDigest.1.3.36.3.2.1", "RIPEMD-160");
    }

    private void addSha1Algorithm() {
        put("MessageDigest.SHA-1", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA1");
        put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
        put("Alg.Alias.MessageDigest.1.3.14.3.2.26", "SHA-1");
    }

    private void addSha2Algorithm() {
        put("MessageDigest.SHA-224", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA224");
        put("Alg.Alias.MessageDigest.SHA224", "SHA-224");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.4", "SHA-224");

        put("MessageDigest.SHA-256", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA256");
        put("Alg.Alias.MessageDigest.SHA256", "SHA-256");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.1", "SHA-256");

        put("MessageDigest.SHA-384", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA384");
        put("Alg.Alias.MessageDigest.SHA384", "SHA-384");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.2", "SHA-384");

        put("MessageDigest.SHA-512", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA512");
        put("Alg.Alias.MessageDigest.SHA2", "SHA-512");
        put("Alg.Alias.MessageDigest.SHA512", "SHA-512");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.3", "SHA-512");
    }

    private void addSha3Algorithm() {
        put("MessageDigest.SHA3-224", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA3_224");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.7", "SHA3-224");

        put("MessageDigest.SHA3-256", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA3_256");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.8", "SHA3-256");

        put("MessageDigest.SHA3-384", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA3_384");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.9", "SHA3-384");

        put("MessageDigest.SHA3-512", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA3_512");
        put("Alg.Alias.MessageDigest.SHA3", "SHA3-512");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.10", "SHA3-512");
    }

    private void addKeccakAlgorithm() {
        put("MessageDigest.KECCAK-224", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Keccak224");
        put("Alg.Alias.MessageDigest.Keccak224", "KECCAK-224");

        put("MessageDigest.KECCAK-256", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Keccak256");
        put("Alg.Alias.MessageDigest.Keccak256", "KECCAK-256");

        put("MessageDigest.KECCAK-384", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Keccak384");
        put("Alg.Alias.MessageDigest.Keccak384", "KECCAK-384");

        put("MessageDigest.KECCAK-512", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Keccak512");
        put("Alg.Alias.MessageDigest.KECCAK", "KECCAK-512");
        put("Alg.Alias.MessageDigest.Keccak512", "KECCAK-512");
    }

    private void addBlake2Algorithm() {
        put("MessageDigest.BLAKE2B-160", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Blake2b160");
        put("Alg.Alias.MessageDigest.Blake2b160", "BLAKE2B-160");
        put("Alg.Alias.MessageDigest.1.3.6.1.4.1.1722.12.2.1.5", "BLAKE2B-160");

        put("MessageDigest.BLAKE2B-256", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Blake2b256");
        put("Alg.Alias.MessageDigest.Blake2b256", "BLAKE2B-256");
        put("Alg.Alias.MessageDigest.1.3.6.1.4.1.1722.12.2.1.8", "BLAKE2B-256");

        put("MessageDigest.BLAKE2B-384", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Blake2b384");
        put("Alg.Alias.MessageDigest.Blake2b384", "BLAKE2B-384");
        put("Alg.Alias.MessageDigest.1.3.6.1.4.1.1722.12.2.1.12", "BLAKE2B-384");

        put("MessageDigest.BLAKE2B-512", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Blake2b512");
        put("Alg.Alias.MessageDigest.BLAKE2B", "BLAKE2B-512");
        put("Alg.Alias.MessageDigest.Blake2b512", "BLAKE2B-512");
        put("Alg.Alias.MessageDigest.1.3.6.1.4.1.1722.12.2.1.16", "BLAKE2B-512");
    }

    private void addHmacAlgorithm() {
        put("Mac.HMAC-MD5", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacMd5");
        put("Alg.Alias.Mac.HmacMD5", "HMAC-MD5");

        put("Mac.HMAC-RIPEMD160", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacRipeMd160");
        put("Alg.Alias.Mac.HmacRipeMd160", "HMAC-RIPEMD160");

        put("Mac.HMAC-SHA1", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha1");
        put("Alg.Alias.Mac.HmacSHA1", "HMAC-SHA1");

        put("Mac.HMAC-SHA224", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha224");
        put("Alg.Alias.Mac.HmacSHA224", "HMAC-SHA224");

        put("Mac.HMAC-SHA256", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha256");
        put("Alg.Alias.Mac.HmacSHA256", "HMAC-SHA256");

        put("Mac.HMAC-SHA384", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha384");
        put("Alg.Alias.Mac.HmacSHA384", "HMAC-SHA384");

        put("Mac.HMAC-SHA512", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha512");
        put("Alg.Alias.Mac.HMAC-SHA2", "HMAC-SHA512");
        put("Alg.Alias.Mac.HmacSHA512", "HMAC-SHA512");
    }

    private void addCmacAlgorithm() {
        put("Mac.CMAC", PACKAGE_NAME + MAC_PREFIX + "BotanMac$CMac");
        put("Alg.Alias.Mac.AESCMAC", "CMAC");
    }

    private void addPoly1305Algorithm() {
        put("Mac.Poly1305", PACKAGE_NAME + MAC_PREFIX + "BotanMac$Poly1305");
    }

    private void addSipHashAlgorithm() {
        put("Mac.SipHash", PACKAGE_NAME + MAC_PREFIX + "BotanMac$SipHash");
    }

    private void addAesAlgorithm() {
        put("Cipher.AES/CBC", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$AesCbc");

        put("Cipher.AES/CFB", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$AesCfb");

        put("Cipher.AES/OFB/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$AesOfb");

        put("Cipher.AES/CTR/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$AesCtr");

        put("Cipher.AES/GCM", PACKAGE_NAME + AEAD_CIPHER_PREFIX + "BotanAeadCipher$AesGcm");

        put("Cipher.AES/CCM", PACKAGE_NAME + AEAD_CIPHER_PREFIX + "BotanAeadCipher$AesCcm");

        put("Cipher.AES/SIV", PACKAGE_NAME + AEAD_CIPHER_PREFIX + "BotanAeadCipher$AesSiv");

        put("Cipher.AES/EAX", PACKAGE_NAME + AEAD_CIPHER_PREFIX + "BotanAeadCipher$AesEax");

        put("Cipher.AES/OCB", PACKAGE_NAME + AEAD_CIPHER_PREFIX + "BotanAeadCipher$AesOcb");
    }

    private void addDesAlgorithm() {
        put("Cipher.DES/CBC", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesCbc");

        put("Cipher.DES/CFB", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesCfb");

        put("Cipher.DES/OFB/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$DesOfb");

        put("Cipher.DES/CTR/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$DesCtr");
    }

    private void addTrippleDesAlgorithm() {
        put("Cipher.DESede/CBC", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbc");
        put("Alg.Alias.Cipher.3DES/CBC", "DESede/CBC");
        put("Alg.Alias.Cipher.TripleDES/CBC", "DESede/CBC");

        put("Cipher.DESede/CFB", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCfb");
        put("Alg.Alias.Cipher.3DES/CFB", "DESede/CFB");
        put("Alg.Alias.Cipher.TripleDES/CFB", "DESede/CFB");

        put("Cipher.DESede/OFB/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$DesEdeOfb");
        put("Cipher.3DES/OFB/NoPadding", "DESede/OFB/NoPadding");
        put("Cipher.TripleDES/OFB/NoPadding", "TripleDES/OFB/NoPadding");

        put("Cipher.DESede/CTR/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$DesEdeCtr");
        put("Cipher.3DES/CTR/NoPadding", "DESede/CTR/NoPadding");
        put("Cipher.TripleDES/CTR/NoPadding", "DESede/CTR/NoPadding");
    }

    private void addSalsa20Algorithm() {
        put("Cipher.Salsa20/None/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$Salsa20");
        put("Cipher.XSalsa20/None/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$XSalsa20");
    }

    private void addChaCha20Algorithm() {
        put("Cipher.ChaCha20/None/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$ChaCha20");
        put("Cipher.XChaCha20/None/NoPadding", PACKAGE_NAME + STREAM_CIPHER_PREFIX + "BotanStreamCipher$XChaCha20");
    }

}
