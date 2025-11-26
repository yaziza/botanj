/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.mac;

import static net.randombit.botan.jnr.BotanInstance.checkNativeCall;
import static net.randombit.botan.jnr.BotanInstance.singleton;
import static net.randombit.botan.util.BotanUtil.checkKeySize;
import static net.randombit.botan.util.BotanUtil.checkSecretKey;

import javax.crypto.MacSpi;
import java.lang.ref.Cleaner;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import jnr.ffi.Pointer;
import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;
import net.randombit.botan.util.BotanUtil;

/**
 * Abstract base class for Message Authentication Code (MAC) implementations using the Botan cryptography library.
 *
 * <p>This class provides a JCE-compliant MAC implementation that delegates cryptographic operations to native
 * Botan library functions via JNR-FFI. It implements automatic native resource management using the Java
 * {@link Cleaner} API to ensure native MAC objects are properly destroyed when no longer needed.</p>
 *
 * <h2>Lifecycle and Resource Management</h2>
 *
 * <p>Native Botan MAC objects are created during initialization and destroyed either:
 * <ul>
 *   <li>Explicitly when re-initializing with a new key (old object destroyed before creating new one)</li>
 *   <li>Automatically by the Cleaner when the Java object becomes unreachable (garbage collection)</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 *
 * <p>This implementation is NOT thread-safe. Each thread should use its own MAC instance. The JCE API
 * does not require MAC implementations to be thread-safe.</p>
 *
 * <h2>State Management</h2>
 *
 * <p>The MAC maintains internal state to optimize reset operations:
 * <ul>
 *   <li>{@code macFinalized} - tracks whether {@code doFinal()} has been called, which auto-resets the state</li>
 *   <li>{@code currentKey} - stores the current key for re-initialization after explicit {@code reset()}</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>Basic HMAC-SHA256 Usage</h3>
 * <pre>{@code
 * // Get MAC instance from the Botan provider
 * Mac mac = Mac.getInstance("HmacSHA256", "Botan");
 *
 * // Initialize with a secret key
 * SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256");
 * mac.init(key);
 *
 * // Update with data
 * mac.update("Hello, ".getBytes());
 * mac.update("World!".getBytes());
 *
 * // Compute the MAC
 * byte[] macValue = mac.doFinal();
 * }</pre>
 *
 * <h3>Incremental Processing with Reset</h3>
 * <pre>{@code
 * Mac mac = Mac.getInstance("HmacSHA256", "Botan");
 * SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256");
 * mac.init(key);
 *
 * // Process first message
 * mac.update(message1);
 * byte[] mac1 = mac.doFinal();  // Auto-resets after doFinal
 *
 * // Process second message (no need to call reset)
 * mac.update(message2);
 * byte[] mac2 = mac.doFinal();
 *
 * // Explicit reset if needed without doFinal
 * mac.update(message3);
 * mac.reset();  // Discard partial computation
 * mac.update(message4);
 * byte[] mac4 = mac.doFinal();
 * }</pre>
 *
 * <h3>Re-initialization with Different Key</h3>
 * <pre>{@code
 * Mac mac = Mac.getInstance("HmacSHA256", "Botan");
 *
 * // First key
 * SecretKeySpec key1 = new SecretKeySpec(keyBytes1, "HmacSHA256");
 * mac.init(key1);
 * byte[] mac1 = mac.doFinal(data1);
 *
 * // Re-initialize with second key (automatically destroys old native object)
 * SecretKeySpec key2 = new SecretKeySpec(keyBytes2, "HmacSHA256");
 * mac.init(key2);  // Old Botan MAC object destroyed, new one created
 * byte[] mac2 = mac.doFinal(data2);
 * }</pre>
 *
 * <h3>Single-Byte Processing</h3>
 * <pre>{@code
 * Mac mac = Mac.getInstance("Poly1305", "Botan");
 * mac.init(key);
 *
 * // Process byte by byte (uses internal single-byte buffer)
 * for (byte b : data) {
 *     mac.update(b);
 * }
 * byte[] result = mac.doFinal();
 * }</pre>
 *
 * <h2>Supported Algorithms</h2>
 *
 * <p>The following MAC algorithms are available through concrete subclasses:
 * <ul>
 *   <li><b>CMAC</b> - {@link CMac} - Cipher-based MAC using AES (16-byte output)</li>
 *   <li><b>Poly1305</b> - {@link Poly1305} - Poly1305 MAC (16-byte output)</li>
 *   <li><b>SipHash</b> - {@link SipHash} - SipHash-2-4 (8-byte output)</li>
 *   <li><b>HMAC-MD5</b> - {@link HMacMd5} - HMAC with MD5 (16-byte output)</li>
 *   <li><b>HMAC-RIPEMD160</b> - {@link HMacRipeMd160} - HMAC with RIPEMD-160 (20-byte output)</li>
 *   <li><b>HMAC-SHA1</b> - {@link HMacSha1} - HMAC with SHA-1 (20-byte output)</li>
 *   <li><b>HMAC-SHA224</b> - {@link HMacSha224} - HMAC with SHA-224 (28-byte output)</li>
 *   <li><b>HMAC-SHA256</b> - {@link HMacSha256} - HMAC with SHA-256 (32-byte output)</li>
 *   <li><b>HMAC-SHA384</b> - {@link HMacSha384} - HMAC with SHA-384 (48-byte output)</li>
 *   <li><b>HMAC-SHA512</b> - {@link HMacSha512} - HMAC with SHA-512 (64-byte output)</li>
 * </ul>
 *
 * <h2>Implementation Notes</h2>
 *
 * <ul>
 *   <li><b>Cloning Not Supported</b> - Calling {@link #clone()} throws {@link CloneNotSupportedException}
 *       because native MAC state cannot be safely cloned</li>
 *   <li><b>Key Size Validation</b> - Key sizes are validated against Botan's key specification during initialization</li>
 *   <li><b>Auto-Reset Optimization</b> - After {@code doFinal()}, the MAC is automatically reset by Botan,
 *       so explicit {@code reset()} is not needed</li>
 *   <li><b>Memory Safety</b> - Native resources are guaranteed to be freed even if explicit cleanup is not called,
 *       thanks to the Cleaner API</li>
 * </ul>
 *
 * @see javax.crypto.MacSpi
 * @see java.lang.ref.Cleaner
 * @author Yasser Aziza
 * @since 0.1.0
 */
public abstract class BotanMac extends MacSpi {

    /**
     * Shared Cleaner instance for all BotanMac instances.
     */
    private static final Cleaner CLEANER = Cleaner.create();
    /**
     * Holds the name of the MAC algorithm.
     */
    private final String name;
    /**
     * Holds the output size of the MAC in bytes.
     */
    private final int size;
    /**
     * Holds the reference to the MAC object referenced by botan.
     */
    private final PointerByReference macRef;
    /**
     * Holds a dummy buffer for writing single bytes to the MAC.
     */
    private final byte[] singleByte = new byte[1];
    /**
     * Cleaner registration for automatic cleanup.
     */
    private Cleaner.Cleanable cleanable;
    /**
     * Tracks whether botan_mac_final has been called since the last update.
     */
    private boolean macFinalized = false;
    /**
     * Stores the key for re-initialization after reset.
     */
    private byte[] currentKey;

    private BotanMac(String name, int size) {
        this.name = name;
        this.size = size;
        this.macRef = new PointerByReference();
    }

    /**
     * Gets the native botan cipher name (e.g. 'CMAC(AES-128)').
     *
     * @param keySize the key size
     * @return {@link String} containing the Botan MAC name.
     */
    protected String getBotanMacName(int keySize) throws InvalidKeyException {
        return name;
    }

    @Override
    protected int engineGetMacLength() {
        return size;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException {
        final byte[] encodedKey = checkSecretKey(key);
        final int length = encodedKey.length;

        // Clean up existing MAC object if re-initializing
        if (cleanable != null) {
            cleanable.clean();
        }

        int err = singleton().botan_mac_init(macRef, getBotanMacName(length), 0);
        checkNativeCall(err, "botan_mac_init");

        // Register cleaner for the newly created MAC object
        cleanable = CLEANER.register(this, new BotanMacCleanupAction(macRef.getValue()));

        BotanUtil.FourParameterFunction<Pointer, NativeLongByReference> getKeySpec = (a, b, c, d) -> {
            return singleton().botan_mac_get_keyspec(a, b, c, d);
        };

        checkKeySize(macRef.getValue(), length, getKeySpec);

        err = singleton().botan_mac_set_key(macRef.getValue(), key.getEncoded(), length);
        checkNativeCall(err, "botan_mac_set_key");

        currentKey = key.getEncoded();
        macFinalized = false;
    }

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;

        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        final byte[] bytes = Arrays.copyOfRange(input, offset, input.length);

        final int err = singleton().botan_mac_update(macRef.getValue(), bytes, len);
        checkNativeCall(err, "botan_mac_update");

        macFinalized = false;
    }

    @Override
    protected byte[] engineDoFinal() {
        final byte[] result = new byte[size];
        final int err = singleton().botan_mac_final(macRef.getValue(), result);
        checkNativeCall(err, "botan_mac_final");

        macFinalized = true;

        return result;
    }

    @Override
    protected void engineReset() {
        // If botan_mac_final has already been called, the MAC is already reset
        if (!macFinalized) {
            // Otherwise, call botan_mac_clear to reset the state and re-set the key
            int err = singleton().botan_mac_clear(macRef.getValue());
            checkNativeCall(err, "botan_mac_clear");

            err = singleton().botan_mac_set_key(macRef.getValue(), currentKey, currentKey.length);
            checkNativeCall(err, "botan_mac_set_key");
        }
        macFinalized = false;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("Cloning is not supported for BotanMac");
    }

    /**
     * Cleanup action for native MAC resources.
     */
    private record BotanMacCleanupAction(jnr.ffi.Pointer macPointer) implements Runnable {

        @Override
        public void run() {
            if (macPointer != null) {
                singleton().botan_mac_destroy(macPointer);
            }
        }
    }

    // CMAC
    public static final class CMac extends BotanMac {
        public CMac() {
            super("CMAC", 16);
        }

        @Override
        public String getBotanMacName(int keySize) {
            return String.format("CMAC(AES-%d)", keySize * Byte.SIZE);
        }
    }

    // HMAC
    public static final class Poly1305 extends BotanMac {
        public Poly1305() {
            super("Poly1305", 16);
        }
    }

    // SipHash
    public static final class SipHash extends BotanMac {
        public SipHash() {
            super("SipHash(2,4)", 8);
        }
    }

    // HMAC
    public static final class HMacMd5 extends BotanMac {
        public HMacMd5() {
            super("HMAC(MD5)", 16);
        }
    }

    public static final class HMacRipeMd160 extends BotanMac {
        public HMacRipeMd160() {
            super("HMAC(RIPEMD-160)", 20);
        }
    }

    public static final class HMacSha1 extends BotanMac {
        public HMacSha1() {
            super("HMAC(SHA-1)", 20);
        }
    }

    public static final class HMacSha224 extends BotanMac {
        public HMacSha224() {
            super("HMAC(SHA-224)", 28);
        }
    }

    public static final class HMacSha256 extends BotanMac {
        public HMacSha256() {
            super("HMAC(SHA-256)", 32);
        }
    }

    public static final class HMacSha384 extends BotanMac {
        public HMacSha384() {
            super("HMAC(SHA-384)", 48);
        }
    }

    public static final class HMacSha512 extends BotanMac {
        public HMacSha512() {
            super("HMAC(SHA-512)", 64);
        }
    }

}
