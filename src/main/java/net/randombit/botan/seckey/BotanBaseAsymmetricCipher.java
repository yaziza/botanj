/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey;

import static net.randombit.botan.Constants.BOTAN_DO_FINAL_FLAG;
import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;
import static net.randombit.botan.jnr.BotanInstance.checkNativeCall;
import static net.randombit.botan.jnr.BotanInstance.singleton;
import static net.randombit.botan.util.BotanUtil.checkKeySize;
import static net.randombit.botan.util.BotanUtil.checkSecretKey;

import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Objects;

import java.lang.ref.Cleaner;

import jnr.ffi.Pointer;
import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;
import net.randombit.botan.util.BotanUtil;

/**
 * Abstract base class for symmetric cipher implementations using the Botan cryptography library.
 *
 * <p>This class provides a JCE-compliant Cipher implementation that delegates cryptographic operations to native
 * Botan library functions via JNR-FFI. It implements automatic native resource management using the Java
 * {@link Cleaner} API to ensure native cipher objects are properly destroyed when no longer needed.</p>
 *
 * <p>The class name "BaseAsymmetricCipher" is a misnomer - it actually implements <b>symmetric</b> ciphers
 * (block ciphers, stream ciphers, and AEAD modes). The name predates the current architecture and is retained
 * for compatibility.</p>
 *
 * <h2>Cipher Categories</h2>
 *
 * <p>This base class supports three main categories of symmetric ciphers:
 * <ul>
 *   <li><b>Block Ciphers</b> - Traditional block cipher modes (CBC, CFB) with padding support</li>
 *   <li><b>Stream Ciphers</b> - Stream modes (CTR, OFB) and native stream ciphers (ChaCha20, Salsa20)</li>
 *   <li><b>AEAD Ciphers</b> - Authenticated encryption modes (GCM, CCM, EAX, OCB, SIV)</li>
 * </ul>
 *
 * <h2>Lifecycle and Resource Management</h2>
 *
 * <p>Native Botan cipher objects are created during initialization and destroyed either:
 * <ul>
 *   <li>Explicitly when re-initializing with a new key (old object destroyed before creating new one)</li>
 *   <li>Automatically by the Cleaner when the Java object becomes unreachable (garbage collection)</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 *
 * <p>This implementation is NOT thread-safe. Each thread should use its own Cipher instance. The JCE API
 * does not require Cipher implementations to be thread-safe.</p>
 *
 * <h2>Initialization and IV/Nonce Management</h2>
 *
 * <p>Ciphers require initialization with a key and optional IV (Initialization Vector) or nonce:
 * <ul>
 *   <li>The IV/nonce must be provided via {@link IvParameterSpec} during initialization</li>
 *   <li>IV/nonce sizes are validated by {@link #isValidNonceLength(int)}</li>
 *   <li>The IV is stored and can be retrieved via {@link #engineGetIV()}</li>
 *   <li><b>Important:</b> Reusing the same IV/nonce with the same key is cryptographically unsafe for most modes</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>Basic AES-CBC Encryption with Padding</h3>
 * <pre>{@code
 * // Get cipher instance from the Botan provider
 * Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7", "Botan");
 *
 * // Generate key and IV
 * SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");  // 16, 24, or 32 bytes
 * IvParameterSpec iv = new IvParameterSpec(ivBytes);        // 16 bytes for AES
 *
 * // Initialize for encryption
 * cipher.init(Cipher.ENCRYPT_MODE, key, iv);
 *
 * // Encrypt data
 * byte[] plaintext = "Secret message".getBytes();
 * byte[] ciphertext = cipher.doFinal(plaintext);
 *
 * // Decrypt
 * cipher.init(Cipher.DECRYPT_MODE, key, iv);
 * byte[] decrypted = cipher.doFinal(ciphertext);
 * }</pre>
 *
 * <h3>Stream Cipher (ChaCha20)</h3>
 * <pre>{@code
 * Cipher cipher = Cipher.getInstance("ChaCha20/None/NoPadding", "Botan");
 *
 * SecretKeySpec key = new SecretKeySpec(keyBytes, "ChaCha20");  // 32 bytes
 * IvParameterSpec nonce = new IvParameterSpec(nonceBytes);      // 8 bytes
 *
 * // Encryption
 * cipher.init(Cipher.ENCRYPT_MODE, key, nonce);
 * byte[] ciphertext = cipher.doFinal(plaintext);
 *
 * // Decryption (same nonce required)
 * cipher.init(Cipher.DECRYPT_MODE, key, nonce);
 * byte[] plaintext = cipher.doFinal(ciphertext);
 * }</pre>
 *
 * <h3>AEAD Mode (AES-GCM) with Authentication</h3>
 * <pre>{@code
 * Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "Botan");
 *
 * SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
 * GCMParameterSpec params = new GCMParameterSpec(128, nonceBytes);  // 128-bit tag, 12-byte nonce
 *
 * // Encryption with authentication
 * cipher.init(Cipher.ENCRYPT_MODE, key, params);
 * cipher.updateAAD(additionalData);  // Optional authenticated data
 * byte[] ciphertext = cipher.doFinal(plaintext);  // Includes authentication tag
 *
 * // Decryption and verification
 * cipher.init(Cipher.DECRYPT_MODE, key, params);
 * cipher.updateAAD(additionalData);  // Must match encryption
 * byte[] plaintext = cipher.doFinal(ciphertext);  // Throws exception if authentication fails
 * }</pre>
 *
 * <h3>Incremental Processing with Update</h3>
 * <pre>{@code
 * Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "Botan");
 * cipher.init(Cipher.ENCRYPT_MODE, key, iv);
 *
 * // Process data incrementally
 * byte[] part1 = cipher.update(data1);
 * byte[] part2 = cipher.update(data2);
 * byte[] part3 = cipher.update(data3);
 * byte[] finalPart = cipher.doFinal();
 *
 * // Combine all parts
 * byte[] complete = concatenate(part1, part2, part3, finalPart);
 * }</pre>
 *
 * <h3>Re-initialization with Different Key</h3>
 * <pre>{@code
 * Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7", "Botan");
 *
 * // First encryption
 * SecretKeySpec key1 = new SecretKeySpec(keyBytes1, "AES");
 * IvParameterSpec iv1 = new IvParameterSpec(ivBytes1);
 * cipher.init(Cipher.ENCRYPT_MODE, key1, iv1);
 * byte[] ciphertext1 = cipher.doFinal(plaintext1);
 *
 * // Re-initialize with different key (automatically destroys old native object)
 * SecretKeySpec key2 = new SecretKeySpec(keyBytes2, "AES");
 * IvParameterSpec iv2 = new IvParameterSpec(ivBytes2);
 * cipher.init(Cipher.ENCRYPT_MODE, key2, iv2);  // Old Botan cipher destroyed, new one created
 * byte[] ciphertext2 = cipher.doFinal(plaintext2);
 * }</pre>
 *
 * <h3>Different Padding Modes</h3>
 * <pre>{@code
 * // PKCS#7 padding (most common)
 * Cipher pkcs7 = Cipher.getInstance("AES/CBC/PKCS7", "Botan");
 *
 * // No padding (plaintext must be multiple of block size)
 * Cipher noPad = Cipher.getInstance("AES/CBC/NoPadding", "Botan");
 *
 * // Other padding schemes
 * Cipher x923 = Cipher.getInstance("AES/CBC/X9.23", "Botan");
 * Cipher oneZero = Cipher.getInstance("AES/CBC/OneAndZeros", "Botan");
 * }</pre>
 *
 * <h2>Cipher Mode Categories and Padding</h2>
 *
 * <p><b>Block Cipher Modes (CBC, CFB):</b>
 * <ul>
 *   <li>Support multiple padding schemes: PKCS7, PKCS5, X9.23, OneAndZeros, ESP, NoPadding</li>
 *   <li>IV size must match the block size of the underlying algorithm (e.g., 16 bytes for AES)</li>
 *   <li>With NoPadding, plaintext length must be a multiple of block size</li>
 * </ul>
 *
 * <p><b>Stream Modes (CTR, OFB, ChaCha20, Salsa20):</b>
 * <ul>
 *   <li>Use "/None/NoPadding" or just "/NoPadding" (no padding needed for stream modes)</li>
 *   <li>Can process any length of plaintext without padding</li>
 *   <li>Nonce/IV sizes vary by algorithm (e.g., 8 bytes for ChaCha20, 16 bytes for AES-CTR)</li>
 * </ul>
 *
 * <p><b>AEAD Modes (GCM, CCM, EAX, OCB, SIV):</b>
 * <ul>
 *   <li>Always use "/NoPadding" (AEAD modes don't use padding)</li>
 *   <li>Provide built-in authentication - no separate MAC needed</li>
 *   <li>Support Additional Authenticated Data (AAD) via {@code updateAAD()}</li>
 *   <li>Nonce sizes vary by mode (typically 12 bytes for GCM)</li>
 * </ul>
 *
 * <h2>Implementation Notes</h2>
 *
 * <ul>
 *   <li><b>Cloning Not Supported</b> - Calling {@link #clone()} throws {@link CloneNotSupportedException}
 *       because native cipher state cannot be safely cloned</li>
 *   <li><b>Key Size Validation</b> - Key sizes are validated against Botan's key specification during initialization</li>
 *   <li><b>Nonce Reuse Warning</b> - The implementation includes a FIXME comment about preventing nonce reuse,
 *       which is a critical security concern for most cipher modes</li>
 *   <li><b>Memory Safety</b> - Native resources are guaranteed to be freed even if explicit cleanup is not called,
 *       thanks to the Cleaner API</li>
 *   <li><b>Mode Setting</b> - The JCE API method {@code setMode()} is not supported because the mode is
 *       specified in the transformation string during {@code getInstance()}</li>
 * </ul>
 *
 * <h2>Concrete Implementations</h2>
 *
 * <p>This class has three main subclass hierarchies:
 * <ul>
 *   <li>{@code BotanBlockCipher} - Block cipher modes (CBC, CFB) with padding</li>
 *   <li>{@code BotanStreamCipher} - Stream modes and stream ciphers</li>
 *   <li>{@code BotanAeadCipher} - Authenticated encryption modes</li>
 * </ul>
 *
 * @see javax.crypto.CipherSpi
 * @see java.lang.ref.Cleaner
 * @author Yasser Aziza
 * @since 0.1.0
 */
public abstract class BotanBaseAsymmetricCipher extends CipherSpi {

    /**
     * Shared Cleaner instance for all BotanBaseAsymmetricCipher instances.
     */
    private static final Cleaner CLEANER = Cleaner.create();
    /**
     * Holds the reference to the cipher object referenced by botan.
     */
    protected final PointerByReference cipherRef;
    /**
     * Holds the name of the cipher algorithm.
     */
    protected final String name;
    /**
     * Holds the Initial Vector (IV).
     */
    protected byte[] iv = EMPTY_BYTE_ARRAY;
    /**
     * Holds the cipher operation mode in native botan terms (0: Encryption, 1: Decryption)
     */
    protected int mode;
    /**
     * Cleaner registration for automatic cleanup.
     */
    private Cleaner.Cleanable cleanable;

    protected BotanBaseAsymmetricCipher(String name) {
        this.name = Objects.requireNonNull(name);
        this.cipherRef = new PointerByReference();
    }

    protected static boolean isDecrypting(int mode) {
        return mode == 1;
    }

    /**
     * Gets the native botan cipher name (e.g. 'AES-128/CBC/PKCS7').
     *
     * @param keyLength the key length
     * @return {@link String} containing the Botan cipher name.
     */
    protected abstract String getBotanCipherName(int keyLength);

    /**
     * Checks whether the given nonce size is supported.
     *
     * @param nonceLength the nonce length
     * @return {@code True} is the given nonce length is supported, {@code False} otherwise.
     */
    protected abstract boolean isValidNonceLength(int nonceLength);

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("Cipher mode not supported " + mode);
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters parameters = null;

        if (iv != null && iv.length > 0) {
            try {
                parameters = AlgorithmParameters.getInstance(name);
                parameters.init(new IvParameterSpec(iv));

            } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                parameters = null;
            }
        }

        return parameters;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            final IvParameterSpec parameterSpec = params.getParameterSpec(IvParameterSpec.class);
            engineInit(opmode, key, parameterSpec, random);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException("Parameters must be convertible to IvParameterSpec", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        engineInit(opmode, key, random);

        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();

            if (!isValidNonceLength(iv.length)) {
                String msg = String.format("Nonce with length %d not allowed for algorithm %s", iv.length, name);
                throw new InvalidAlgorithmParameterException(msg);
            }

            final int err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");

        } else {
            throw new InvalidAlgorithmParameterException("Error: Missing or invalid IvParameterSpec provided !");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        final byte[] encodedKey = checkSecretKey(key);
        final int keySize = encodedKey.length;

        final String algName = getBotanCipherName(keySize);

        // Translate java cipher mode to botan native mode (0: Encryption, 1: Decryption)
        mode = Math.subtractExact(opmode, 1);

        // Clean up existing cipher object if re-initializing
        if (cleanable != null) {
            cleanable.clean();
        }

        int err = singleton().botan_cipher_init(cipherRef, algName, mode);
        checkNativeCall(err, "botan_cipher_init");

        // Register cleaner for the newly created cipher object
        cleanable = CLEANER.register(this, new net.randombit.botan.seckey.BotanBaseAsymmetricCipher.BotanCipherCleanupAction(cipherRef.getValue()));

        BotanUtil.FourParameterFunction<Pointer, NativeLongByReference> getKeySpec = (a, b, c, d) -> {
            return singleton().botan_cipher_get_keyspec(a, b, c, d);
        };

        checkKeySize(cipherRef.getValue(), keySize, getKeySpec);

        err = singleton().botan_cipher_set_key(cipherRef.getValue(), encodedKey, keySize);
        checkNativeCall(err, "botan_cipher_set_key");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        final byte[] result = engineUpdate(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);

        return result.length;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws IllegalBlockSizeException {
        final byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);

        return result.length;
    }

    @Override
    protected abstract byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException;

    protected byte[] doCipher(byte[] input, int inputLength, int botanFlag) {
        final NativeLongByReference outputWritten = new NativeLongByReference();
        final NativeLongByReference inputConsumed = new NativeLongByReference();

        final byte[] output = new byte[engineGetOutputSize(inputLength)];

        final int err = singleton().botan_cipher_update(cipherRef.getValue(), botanFlag,
                output, output.length, outputWritten,
                input, input.length, inputConsumed);

        checkNativeCall(err, "botan_cipher_update");

        final byte[] result = Arrays.copyOfRange(output, 0, outputWritten.intValue());

        if (BOTAN_DO_FINAL_FLAG == botanFlag) {
            engineReset();
        }

        return result;
    }

    protected void engineReset() {
        int err = singleton().botan_cipher_reset(cipherRef.getValue());
        checkNativeCall(err, "botan_cipher_reset");

        if (iv != null) {
            //FIXME: nonce reuse - disable starting cipher with same IV
            err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("Cloning is not supported for BotanBaseAsymmetricCipher");
    }

    /**
     * Cleanup action for native Cipher resources.
     */
    private record BotanCipherCleanupAction(jnr.ffi.Pointer cipherPointer) implements Runnable {

        @Override
        public void run() {
            if (cipherPointer != null) {
                singleton().botan_cipher_destroy(cipherPointer);
            }
        }
    }

}
