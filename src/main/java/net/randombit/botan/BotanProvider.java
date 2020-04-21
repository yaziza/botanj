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

    public static final String PROVIDER_NAME = "Botan";
    private static final String PROVIDER_INFO = "Botan Java Security Provider";

    private static final String PACKAGE_NAME = BotanProvider.class.getPackage().getName();
    private static final String DIGEST_PREFIX = ".digest.";

    private static final BotanNative BOTAN_NATIVE = Botan.getInstance();

    public BotanProvider() {
        super(PROVIDER_NAME, 0, PROVIDER_INFO);

        // Message Digests
        addMdAlgorithms();
        addSha1Algorithms();
        addSha2Algorithms();
        addSha3Algorithms();
        addKeccakAlgorithms();
        addBlake2Algorithms();
    }

    @Override
    public String getInfo() {
        return PROVIDER_INFO;
    }

    @Override
    public double getVersion() {
        return BOTAN_NATIVE.botan_ffi_api_version();
    }

    @Override
    public String toString() {
        return BOTAN_NATIVE.botan_version_string();
    }

    private void addMdAlgorithms() {
        put("MessageDigest.RIPEMD-160", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$RipeMd160");
        put("Alg.Alias.MessageDigest.RIPEMD160", "RIPEMD-160");
        put("Alg.Alias.MessageDigest.1.3.36.3.2.1", "RIPEMD-160");
    }

    private void addSha1Algorithms() {
        put("MessageDigest.SHA-1", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA1");
        put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
        put("Alg.Alias.MessageDigest.1.3.14.3.2.26", "SHA-1");
    }

    private void addSha2Algorithms() {
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
        put("Alg.Alias.MessageDigest.SHA512", "SHA-512");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.3", "SHA-512");
    }

    private void addSha3Algorithms() {
        put("MessageDigest.SHA3-224", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA3_224");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.7", "SHA3-224");

        put("MessageDigest.SHA3-256", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA3_256");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.8", "SHA3-256");

        put("MessageDigest.SHA3-384", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA3_384");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.9", "SHA3-384");

        put("MessageDigest.SHA3-512", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$SHA3_512");
        put("Alg.Alias.MessageDigest.2.16.840.1.101.3.4.2.10", "SHA3-512");
    }

    private void addKeccakAlgorithms() {
        put("MessageDigest.KECCAK-224", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Keccak224");
        put("Alg.Alias.MessageDigest.Keccak224", "KECCAK-224");

        put("MessageDigest.KECCAK-256", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Keccak256");
        put("Alg.Alias.MessageDigest.Keccak256", "KECCAK-256");

        put("MessageDigest.KECCAK-384", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Keccak384");
        put("Alg.Alias.MessageDigest.Keccak384", "KECCAK-384");

        put("MessageDigest.KECCAK-512", PACKAGE_NAME + DIGEST_PREFIX + "BotanMessageDigest$Keccak512");
        put("Alg.Alias.MessageDigest.Keccak512", "KECCAK-512");
    }

    private void addBlake2Algorithms() {
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
        put("Alg.Alias.MessageDigest.Blake2b512", "BLAKE2B-512");
        put("Alg.Alias.MessageDigest.1.3.6.1.4.1.1722.12.2.1.16", "BLAKE2B-512");
    }

}
