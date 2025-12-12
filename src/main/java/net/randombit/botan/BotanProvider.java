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

/**
 * Java Security Provider implementation that provides cryptographic algorithms using the Botan native library.
 *
 * <p>This provider integrates the Botan cryptography library into the Java Cryptography Architecture (JCA),
 * making Botan's high-performance native implementations available through standard JCA APIs. All cryptographic
 * operations are delegated to the native Botan library via JNR-FFI.</p>
 *
 * <h2>Installation and Usage</h2>
 *
 * <p>The provider can be registered statically in the security properties file or dynamically at runtime:</p>
 *
 * <h3>Static Registration (java.security file)</h3>
 * <pre>
 * security.provider.N=net.randombit.botan.BotanProvider
 * </pre>
 *
 * <h3>Dynamic Registration</h3>
 * <pre>{@code
 * // Add as highest priority provider
 * Security.insertProviderAt(new BotanProvider(), 1);
 *
 * // Or add at lowest priority
 * Security.addProvider(new BotanProvider());
 * }</pre>
 *
 * <h3>Using Algorithms from This Provider</h3>
 * <pre>{@code
 * // Explicitly request from Botan provider
 * MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "Botan");
 * Mac hmac = Mac.getInstance("HmacSHA256", "Botan");
 * Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "Botan");
 *
 * // Or use provider object
 * MessageDigest sha256 = MessageDigest.getInstance("SHA-256", new BotanProvider());
 * }</pre>
 *
 * <h2>Supported Algorithms</h2>
 *
 * <h3>Message Digests (Hash Functions)</h3>
 * <ul>
 *   <li><b>MD Family:</b> MD4, MD5 (deprecated for security)</li>
 *   <li><b>SHA-1:</b> SHA-1 (deprecated for security)</li>
 *   <li><b>SHA-2 Family:</b> SHA-224, SHA-256, SHA-384, SHA-512</li>
 *   <li><b>SHA-3 Family:</b> SHA3-224, SHA3-256, SHA3-384, SHA3-512</li>
 *   <li><b>Keccak:</b> KECCAK-224, KECCAK-256, KECCAK-384, KECCAK-512</li>
 *   <li><b>BLAKE2b:</b> BLAKE2B-160, BLAKE2B-256, BLAKE2B-384, BLAKE2B-512</li>
 *   <li><b>RIPEMD:</b> RIPEMD-160</li>
 * </ul>
 *
 * <h3>Message Authentication Codes (MACs)</h3>
 * <ul>
 *   <li><b>HMAC:</b> HMAC-MD5, HMAC-RIPEMD160, HMAC-SHA1, HMAC-SHA224, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512</li>
 *   <li><b>CMAC:</b> CMAC (AES-based cipher MAC)</li>
 *   <li><b>Poly1305:</b> Poly1305</li>
 *   <li><b>SipHash:</b> SipHash (SipHash-2-4)</li>
 * </ul>
 *
 * <h3>Symmetric Ciphers</h3>
 *
 * <p><b>AES (Advanced Encryption Standard):</b></p>
 * <ul>
 *   <li>Block modes: AES/CBC, AES/CFB</li>
 *   <li>Stream modes: AES/CTR/NoPadding, AES/OFB/NoPadding</li>
 *   <li>AEAD modes: AES/GCM, AES/CCM, AES/SIV, AES/EAX, AES/OCB</li>
 * </ul>
 *
 * <p><b>DES (Data Encryption Standard):</b></p>
 * <ul>
 *   <li>Block modes: DES/CBC, DES/CFB</li>
 *   <li>Stream modes: DES/CTR/NoPadding, DES/OFB/NoPadding</li>
 * </ul>
 *
 * <p><b>Triple DES (3DES/DESede):</b></p>
 * <ul>
 *   <li>Block modes: DESede/CBC, DESede/CFB (also aliased as 3DES and TripleDES)</li>
 *   <li>Stream modes: DESede/CTR/NoPadding, DESede/OFB/NoPadding</li>
 * </ul>
 *
 * <p><b>Stream Ciphers:</b></p>
 * <ul>
 *   <li>Salsa20/None/NoPadding, XSalsa20/None/NoPadding</li>
 *   <li>ChaCha20/None/NoPadding, XChaCha20/None/NoPadding</li>
 * </ul>
 *
 * <h3>Random Number Generators</h3>
 * <ul>
 *   <li><b>BotanSystem (System RNG):</b> OS-provided entropy source (default, thread-safe)</li>
 *   <li><b>BotanUser:</b> User-space ChaCha20-based CSPRNG (fast, not thread-safe)</li>
 *   <li><b>BotanUserThreadsafe:</b> Thread-safe user-space CSPRNG</li>
 * </ul>
 *
 * <h2>Padding Schemes for Block Ciphers</h2>
 *
 * <p>Block cipher modes (CBC, CFB) support the following padding schemes:</p>
 * <ul>
 *   <li><b>PKCS7</b> - PKCS#7 padding (most common, recommended)</li>
 *   <li><b>PKCS5</b> - PKCS#5 padding (equivalent to PKCS7 for 8-byte blocks)</li>
 *   <li><b>X9.23</b> - ANSI X9.23 padding</li>
 *   <li><b>OneAndZeros</b> - ISO/IEC 7816-4 padding</li>
 *   <li><b>ESP</b> - ESP padding (RFC 4303)</li>
 *   <li><b>NoPadding</b> - No padding (plaintext must be multiple of block size)</li>
 * </ul>
 *
 * <p>Example: {@code Cipher.getInstance("AES/CBC/PKCS7", "Botan")}</p>
 *
 * <h2>Algorithm Aliases</h2>
 *
 * <p>This provider supports multiple aliases for convenience and compatibility:</p>
 * <ul>
 *   <li><b>SHA-256</b> can also be accessed as "SHA256"</li>
 *   <li><b>HmacSHA256</b> is an alias for "HMAC-SHA256"</li>
 *   <li><b>AESCMAC</b> is an alias for "CMAC"</li>
 *   <li><b>3DES/CBC</b> and <b>TripleDES/CBC</b> are aliases for "DESede/CBC"</li>
 *   <li>OID aliases are supported for standard algorithms (e.g., "2.16.840.1.101.3.4.2.1" for SHA-256)</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>Computing a Hash</h3>
 * <pre>{@code
 * Security.addProvider(new BotanProvider());
 *
 * MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "Botan");
 * sha256.update("Hello, World!".getBytes());
 * byte[] hash = sha256.digest();
 * }</pre>
 *
 * <h3>HMAC Authentication</h3>
 * <pre>{@code
 * Mac hmac = Mac.getInstance("HmacSHA256", "Botan");
 * SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256");
 * hmac.init(key);
 * hmac.update(message);
 * byte[] mac = hmac.doFinal();
 * }</pre>
 *
 * <h3>AES Encryption with GCM (AEAD)</h3>
 * <pre>{@code
 * Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "Botan");
 * SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
 * GCMParameterSpec params = new GCMParameterSpec(128, nonceBytes);
 *
 * cipher.init(Cipher.ENCRYPT_MODE, key, params);
 * cipher.updateAAD(additionalData);
 * byte[] ciphertext = cipher.doFinal(plaintext);
 * }</pre>
 *
 * <h3>ChaCha20 Stream Cipher</h3>
 * <pre>{@code
 * Cipher cipher = Cipher.getInstance("ChaCha20/None/NoPadding", "Botan");
 * SecretKeySpec key = new SecretKeySpec(keyBytes, "ChaCha20");
 * IvParameterSpec nonce = new IvParameterSpec(nonceBytes);
 *
 * cipher.init(Cipher.ENCRYPT_MODE, key, nonce);
 * byte[] ciphertext = cipher.doFinal(plaintext);
 * }</pre>
 *
 * <h2>Provider Information</h2>
 *
 * <p>Provider name: {@value #NAME}</p>
 * <p>Provider info: {@value #INFO}</p>
 * <p>Version: Determined by the native Botan library version (accessible via {@link #getVersionStr()})</p>
 *
 * <h2>Native Library Requirements</h2>
 *
 * <p>This provider requires the Botan 3.x native library to be installed and accessible:</p>
 * <ul>
 *   <li><b>Library name:</b> botan-3 (libbotan-3.so on Linux, libbotan-3.dylib on macOS, botan-3.dll on Windows)</li>
 *   <li><b>Minimum version:</b> Botan 3.0.0</li>
 *   <li><b>Installation:</b> Via system package manager or built from source</li>
 *   <li><b>Path configuration:</b> Library must be in system library path or specified via java.library.path</li>
 * </ul>
 *
 * <p>If the native library cannot be loaded, the provider will throw an exception during construction.</p>
 *
 * <h2>Compatibility</h2>
 *
 * <p>This provider is designed to be compatible with other JCE providers:</p>
 * <ul>
 *   <li>Can be used alongside SunJCE, BouncyCastle, and other providers</li>
 *   <li>Follows standard JCA naming conventions and APIs</li>
 *   <li>Supports OID-based algorithm requests for interoperability</li>
 *   <li>Algorithm implementations produce compatible outputs with standard implementations</li>
 * </ul>
 *
 * <h2>Implementation Notes</h2>
 *
 * <ul>
 *   <li><b>Performance:</b> Algorithms delegate to native Botan library for optimal performance</li>
 *   <li><b>Resource Management:</b> Uses Java Cleaner API for automatic native resource cleanup</li>
 *   <li><b>Thread Safety:</b> The provider itself is thread-safe, but individual cipher/digest instances are not</li>
 *   <li><b>Immutability:</b> The provider is final and cannot be extended</li>
 *   <li><b>Initialization:</b> Provider checks native library availability during construction</li>
 * </ul>
 *
 * @author Yasser Aziza
 * @see java.security.Provider
 * @see net.randombit.botan.jnr.BotanInstance
 * @since 0.1.0
 */
public final class BotanProvider extends Provider {

    /**
     * The name of this security provider ("Botan").
     * Used when requesting cryptographic services from this provider.
     */
    public static final String NAME = "Botan";
    private static final String INFO = "Botan Java Security Provider";

    private static final String PACKAGE_NAME = BotanProvider.class.getPackage().getName();
    private static final String DIGEST_PREFIX = ".digest.";
    private static final String MAC_PREFIX = ".mac.";
    private static final String BLOCK_CIPHER_PREFIX = ".seckey.block.";
    private static final String STREAM_CIPHER_PREFIX = ".seckey.stream.";
    private static final String AEAD_CIPHER_PREFIX = ".seckey.block.aead.";
    private static final String RNG_PREFIX = ".rng.";

    private static final BotanLibrary NATIVE = BotanInstance.singleton();

    /**
     * Constructs a new BotanProvider and registers all supported cryptographic algorithms.
     *
     * @throws UnsatisfiedLinkError if the Botan native library cannot be loaded
     */
    public BotanProvider() {
        super(NAME, "", INFO);

        BotanInstance.checkAvailability();

        // Random Number Generators
        addRngAlgorithm();

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

    private void addRngAlgorithm() {
        put("SecureRandom.Botan", PACKAGE_NAME + RNG_PREFIX + "BotanSecureRandom$SystemRng");
        put("Alg.Alias.SecureRandom.BotanSystem", "Botan");
        put("SecureRandom.Botan ThreadSafe", "true");

        put("SecureRandom.BotanUser", PACKAGE_NAME + RNG_PREFIX + "BotanSecureRandom$UserRng");
        put("SecureRandom.BotanUser ThreadSafe", "false");

        put("SecureRandom.BotanUserThreadsafe", PACKAGE_NAME + RNG_PREFIX + "BotanSecureRandom$UserThreadsafeRng");
        put("SecureRandom.BotanUserThreadsafe ThreadSafe", "true");
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

        put("Cipher.ChaCha20/Poly1305", PACKAGE_NAME + AEAD_CIPHER_PREFIX + "BotanAeadCipher$ChaCha20Poly1305");
        put("Alg.Alias.Cipher.ChaCha20Poly1305", "ChaCha20/Poly1305");
        put("Alg.Alias.Cipher.ChaCha20-Poly1305", "ChaCha20/Poly1305");

        put("Cipher.XChaCha20/Poly1305", PACKAGE_NAME + AEAD_CIPHER_PREFIX + "BotanAeadCipher$XChaCha20Poly1305");
        put("Alg.Alias.Cipher.XChaCha20Poly1305", "XChaCha20/Poly1305");
        put("Alg.Alias.Cipher.XChaCha20-Poly1305", "XChaCha20/Poly1305");
    }

}
