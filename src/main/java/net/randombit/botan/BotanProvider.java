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

public final class BotanProvider extends Provider {

    public static final String NAME = "Botan";
    private static final String INFO = "Botan Java Security Provider";

    private static final String PACKAGE_NAME = BotanProvider.class.getPackage().getName();
    private static final String DIGEST_PREFIX = ".digest.";
    private static final String MAC_PREFIX = ".mac.";
    private static final String BLOCK_CIPHER_PREFIX = ".block.";

    private static final BotanNative NATIVE = Botan.singleton();

    public BotanProvider() {
        super(NAME, 0, INFO);

        Botan.checkAvailability();

        // Message Digests
        addMdAlgorithm();
        addSha1Algorithm();
        addSha2Algorithm();
        addSha3Algorithm();
        addKeccakAlgorithm();
        addBlake2Algorithm();

        // Message Authentication Codes
        addHmacAlgorithm();

        // Block Ciphers
        addAesAlgorithm();
        addDesAlgorithm();
        addTrippleDesAlgorithm();
    }

    @Override
    public String getInfo() {
        return INFO;
    }

    @Override
    public double getVersion() {
        return NATIVE.botan_ffi_api_version();
    }

    @Override
    public String toString() {
        return NATIVE.botan_version_string();
    }

    private void addMdAlgorithm() {
        put("MessageDigest.MD4", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$MD4");
        put("Alg.Alias.MessageDigest.MD4", "MD4");
        put("Alg.Alias.MessageDigest.1.3.6.1.4.1.37476.3.2.1.99.1", "MD4");

        put("MessageDigest.MD5", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$MD5");
        put("Alg.Alias.MessageDigest.MD5", "MD5");
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
        put("Alg.Alias.Mac.HmacMD5", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacMd5");

        put("Mac.HMAC-RIPEMD160", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacRipeMd160");
        put("Alg.Alias.Mac.HmacRipeMd160", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacRipeMd160");

        put("Mac.HMAC-SHA1", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha1");
        put("Alg.Alias.Mac.HmacSHA1", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha1");

        put("Mac.HMAC-SHA224", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha224");
        put("Alg.Alias.Mac.HmacSHA224", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha224");

        put("Mac.HMAC-SHA256", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha256");
        put("Alg.Alias.Mac.HmacSHA256", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha256");

        put("Mac.HMAC-SHA384", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha384");
        put("Alg.Alias.Mac.HmacSHA384", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha384");

        put("Mac.HMAC-SHA512", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha512");
        put("Mac.HMAC-SHA2", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha512");
        put("Alg.Alias.Mac.HmacSHA512", PACKAGE_NAME + MAC_PREFIX + "BotanMac$HMacSha512");
    }

    private void addAesAlgorithm() {
        put("Cipher.AES/CBC/NoPadding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$AesCbcNoPadding");
        put("Cipher.AES/CBC/PKCS7", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$AesCbcPkcs7");
        put("Cipher.AES/CBC/PKCS5Padding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$AesCbcPkcs7");
        put("Cipher.AES/CBC/OneAndZeros", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$AesCbcIso");
        put("Cipher.AES/CBC/X9.23", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$AesCbcX923");
        put("Cipher.AES/CBC/ESP", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$AesCbcEsp");
    }

    private void addDesAlgorithm() {
        put("Cipher.DES/CBC/NoPadding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesCbcNoPadding");
        put("Cipher.DES/CBC/PKCS7", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesCbcPkcs7");
        put("Cipher.DES/CBC/PKCS5Padding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesCbcPkcs7");
        put("Cipher.DES/CBC/OneAndZeros", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesCbcIso");
        put("Cipher.DES/CBC/X9.23", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesCbcX923");
        put("Cipher.DES/CBC/ESP", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesCbcEsp");
    }

    private void addTrippleDesAlgorithm() {
        put("Cipher.DESede/CBC/NoPadding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcNoPadding");
        put("Cipher.3DES/CBC/NoPadding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcNoPadding");
        put("Cipher.TripleDES/CBC/NoPadding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcNoPadding");

        put("Cipher.DESede/CBC/PKCS7", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcPkcs7");
        put("Cipher.DESede/CBC/PKCS5Padding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcPkcs7");
        put("Cipher.3DES/CBC/PKCS7", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcPkcs7");
        put("Cipher.3DES/CBC/PKCS5Padding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcPkcs7");
        put("Cipher.TripleDES/CBC/PKCS7", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcPkcs7");
        put("Cipher.TripleDES/CBC/PKCS5Padding", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcPkcs7");

        put("Cipher.DESede/CBC/OneAndZeros", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcIso");
        put("Cipher.3DES/CBC/OneAndZeros", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcIso");
        put("Cipher.TripleDES/CBC/OneAndZeros", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcIso");

        put("Cipher.DESede/CBC/X9.23", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcX923");
        put("Cipher.TripleDES/CBC/X9.23", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcX923");
        put("Cipher.3DES/CBC/X9.23", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcX923");

        put("Cipher.DESede/CBC/ESP", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcEsp");
        put("Cipher.3DES/CBC/ESP", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcEsp");
        put("Cipher.TripleDES/CBC/ESP", PACKAGE_NAME + BLOCK_CIPHER_PREFIX + "BotanBlockCipher$DesEdeCbcEsp");
    }

}
