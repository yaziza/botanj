/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.digest;

import static net.randombit.botan.jnr.BotanInstance.checkNativeCall;
import static net.randombit.botan.jnr.BotanInstance.singleton;

import java.lang.ref.Cleaner;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import jnr.ffi.byref.PointerByReference;

/**
 * Message digest (cryptographic hash) implementation using the Botan cryptography library.
 *
 * <p>This class provides a JCE-compliant MessageDigest implementation that delegates hash computations to native
 * Botan library functions via JNR-FFI. It implements automatic native resource management using the Java
 * {@link Cleaner} API to ensure native hash objects are properly destroyed when no longer needed.</p>
 *
 * <h2>Lifecycle and Resource Management</h2>
 *
 * <p>Native Botan hash objects are created during construction and destroyed automatically by the Cleaner when the
 * Java object becomes unreachable (garbage collection). Unlike MAC and Cipher implementations, MessageDigest objects
 * are not re-initializable - once created, they maintain the same hash algorithm for their entire lifetime.</p>
 *
 * <h2>Thread Safety</h2>
 *
 * <p>This implementation is NOT thread-safe. Each thread should use its own MessageDigest instance. The JCE API
 * does not require MessageDigest implementations to be thread-safe.</p>
 *
 * <h2>Cloning Support</h2>
 *
 * <p>This implementation supports cloning via {@link #clone()}. When a MessageDigest is cloned, the native hash
 * state is copied using Botan's {@code botan_hash_copy_state} function, allowing independent computation of
 * digests from the same intermediate state. Each cloned instance maintains its own native resource that is
 * independently managed by the Cleaner.</p>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>Basic SHA-256 Hash</h3>
 * <pre>{@code
 * // Get MessageDigest instance from the Botan provider
 * MessageDigest digest = MessageDigest.getInstance("SHA-256", "Botan");
 *
 * // Update with data
 * digest.update("Hello, World!".getBytes());
 *
 * // Compute the hash
 * byte[] hash = digest.digest();
 * }</pre>
 *
 * <h3>Incremental Hashing with Multiple Updates</h3>
 * <pre>{@code
 * MessageDigest digest = MessageDigest.getInstance("SHA-256", "Botan");
 *
 * // Process data incrementally
 * digest.update("Part 1 ".getBytes());
 * digest.update("Part 2 ".getBytes());
 * digest.update("Part 3".getBytes());
 *
 * // Finalize and get result
 * byte[] hash = digest.digest();
 * }</pre>
 *
 * <h3>Digest and Reset for Multiple Messages</h3>
 * <pre>{@code
 * MessageDigest digest = MessageDigest.getInstance("SHA-512", "Botan");
 *
 * // Hash first message
 * digest.update(message1);
 * byte[] hash1 = digest.digest();  // Auto-resets after digest
 *
 * // Hash second message
 * digest.update(message2);
 * byte[] hash2 = digest.digest();
 *
 * // Explicit reset if needed without digest
 * digest.update(message3);
 * digest.reset();  // Discard partial computation
 * digest.update(message4);
 * byte[] hash4 = digest.digest();
 * }</pre>
 *
 * <h3>Cloning for Branch Computation</h3>
 * <pre>{@code
 * MessageDigest digest = MessageDigest.getInstance("SHA-256", "Botan");
 *
 * // Common prefix
 * digest.update("Common prefix: ".getBytes());
 *
 * // Clone to create independent branches
 * MessageDigest branch1 = (MessageDigest) digest.clone();
 * MessageDigest branch2 = (MessageDigest) digest.clone();
 *
 * // Compute different hashes from same prefix
 * branch1.update("branch 1 data".getBytes());
 * byte[] hash1 = branch1.digest();
 *
 * branch2.update("branch 2 data".getBytes());
 * byte[] hash2 = branch2.digest();
 *
 * // Original digest is unchanged
 * digest.update("original continuation".getBytes());
 * byte[] hash3 = digest.digest();
 * }</pre>
 *
 * <h3>Single-Byte Processing</h3>
 * <pre>{@code
 * MessageDigest digest = MessageDigest.getInstance("BLAKE2b-256", "Botan");
 *
 * // Process byte by byte (uses internal single-byte buffer)
 * for (byte b : data) {
 *     digest.update(b);
 * }
 * byte[] result = digest.digest();
 * }</pre>
 *
 * <h3>One-Shot Hashing</h3>
 * <pre>{@code
 * MessageDigest digest = MessageDigest.getInstance("SHA-256", "Botan");
 *
 * // Compute hash in single call (combines update + digest)
 * byte[] hash = digest.digest(data);
 * }</pre>
 *
 * <h2>Supported Algorithms</h2>
 *
 * <p>The following hash algorithms are available through concrete subclasses:
 * <ul>
 *   <li><b>SHA-1</b> - {@link SHA1} - SHA-1 (20-byte output) - <i>Not recommended for security-critical applications</i></li>
 *   <li><b>SHA-224</b> - {@link SHA224} - SHA-2 family (28-byte output)</li>
 *   <li><b>SHA-256</b> - {@link SHA256} - SHA-2 family (32-byte output)</li>
 *   <li><b>SHA-384</b> - {@link SHA384} - SHA-2 family (48-byte output)</li>
 *   <li><b>SHA-512</b> - {@link SHA512} - SHA-2 family (64-byte output)</li>
 *   <li><b>SHA-3(224)</b> - {@link SHA3_224} - SHA-3 family (28-byte output)</li>
 *   <li><b>SHA-3(256)</b> - {@link SHA3_256} - SHA-3 family (32-byte output)</li>
 *   <li><b>SHA-3(384)</b> - {@link SHA3_384} - SHA-3 family (48-byte output)</li>
 *   <li><b>SHA-3(512)</b> - {@link SHA3_512} - SHA-3 family (64-byte output)</li>
 *   <li><b>Keccak-1600(224)</b> - {@link Keccak224} - Keccak (28-byte output)</li>
 *   <li><b>Keccak-1600(256)</b> - {@link Keccak256} - Keccak (32-byte output)</li>
 *   <li><b>Keccak-1600(384)</b> - {@link Keccak384} - Keccak (48-byte output)</li>
 *   <li><b>Keccak-1600(512)</b> - {@link Keccak512} - Keccak (64-byte output)</li>
 *   <li><b>Blake2b(160)</b> - {@link Blake2b160} - BLAKE2b (20-byte output)</li>
 *   <li><b>Blake2b(256)</b> - {@link Blake2b256} - BLAKE2b (32-byte output)</li>
 *   <li><b>Blake2b(384)</b> - {@link Blake2b384} - BLAKE2b (48-byte output)</li>
 *   <li><b>Blake2b(512)</b> - {@link Blake2b512} - BLAKE2b (64-byte output)</li>
 *   <li><b>MD4</b> - {@link MD4} - MD4 (16-byte output) - <i>Not recommended for security-critical applications</i></li>
 *   <li><b>MD5</b> - {@link MD5} - MD5 (16-byte output) - <i>Not recommended for security-critical applications</i></li>
 *   <li><b>RIPEMD-160</b> - {@link RipeMd160} - RIPEMD-160 (20-byte output)</li>
 * </ul>
 *
 * <h2>Implementation Notes</h2>
 *
 * <ul>
 *   <li><b>Cloning Supported</b> - Unlike MAC and Cipher, MessageDigest supports cloning via native state copy</li>
 *   <li><b>Immutable Algorithm</b> - The hash algorithm cannot be changed after construction</li>
 *   <li><b>Auto-Reset After Digest</b> - After {@code digest()}, the state is automatically reset by Botan</li>
 *   <li><b>Memory Safety</b> - Native resources are guaranteed to be freed even if explicit cleanup is not called,
 *       thanks to the Cleaner API</li>
 *   <li><b>Performance</b> - Delegates to native Botan implementation for optimal performance</li>
 * </ul>
 *
 * @author Yasser Aziza
 * @see java.security.MessageDigestSpi
 * @see java.lang.ref.Cleaner
 * @since 0.1.0
 */
public class BotanMessageDigest extends MessageDigestSpi implements Cloneable {

    /**
     * Shared Cleaner instance for all BotanMessageDigest instances.
     */
    private static final Cleaner CLEANER = Cleaner.create();
    /**
     * Holds the name of the hashing algorithm.
     */
    private final String name;
    /**
     * Holds the output size of the message digest in bytes.
     */
    private final int size;
    /**
     * Holds the reference to the hash object referenced by botan.
     */
    private final PointerByReference hashRef;
    /**
     * Cleaner registration for automatic cleanup.
     */
    private final Cleaner.Cleanable cleanable;
    /**
     * Holds a dummy buffer for writing single bytes to the hash.
     */
    private final byte[] singleByte = new byte[1];

    private BotanMessageDigest(String name, int size) throws NoSuchAlgorithmException {
        this.name = name;
        this.size = size;
        this.hashRef = new PointerByReference();

        final int err = singleton().botan_hash_init(hashRef, name, 0);
        checkNativeCall(err, "botan_hash_init");

        // Register cleaner for automatic cleanup on GC
        this.cleanable = CLEANER.register(this, new BotanHashCleanupAction(hashRef.getValue()));
    }

    private BotanMessageDigest(String name, int size, PointerByReference hashRef) {
        this.name = name;
        this.size = size;
        this.hashRef = hashRef;

        // Register cleaner for cloned instances as well
        this.cleanable = CLEANER.register(this, new BotanHashCleanupAction(hashRef.getValue()));
    }

    @Override
    protected int engineGetDigestLength() {
        return size;
    }

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;

        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        final byte[] bytes = Arrays.copyOfRange(input, offset, input.length);

        final int err = singleton().botan_hash_update(hashRef.getValue(), bytes, len);
        checkNativeCall(err, "botan_hash_update");
    }

    @Override
    protected byte[] engineDigest() {
        final byte[] result = new byte[size];
        final int err = singleton().botan_hash_final(hashRef.getValue(), result);
        checkNativeCall(err, "botan_hash_final");

        return result;
    }

    @Override
    protected void engineReset() {
        final int err = singleton().botan_hash_clear(hashRef.getValue());
        checkNativeCall(err, "botan_hash_clear");
    }

    @Override
    public Object clone() {
        final PointerByReference clone = new PointerByReference();
        final int err = singleton().botan_hash_copy_state(clone, hashRef.getValue());
        checkNativeCall(err, "botan_hash_copy_state");

        return new BotanMessageDigest(name, size, clone);
    }

    /**
     * Cleanup action for native hash resources.
     */
    private record BotanHashCleanupAction(jnr.ffi.Pointer hashPointer) implements Runnable {

        @Override
        public void run() {
            if (hashPointer != null) {
                singleton().botan_hash_destroy(hashPointer);
            }
        }
    }

    /**
     * SHA-1 message digest implementation (160-bit output).
     */
    public static final class SHA1 extends BotanMessageDigest {
        /**
         * Constructs a new SHA-1 message digest.
         *
         * @throws NoSuchAlgorithmException if SHA-1 is not available
         */
        public SHA1() throws NoSuchAlgorithmException {
            super("SHA-1", 20);
        }
    }

    /**
     * SHA-224 message digest implementation (224-bit output).
     */
    public static final class SHA224 extends BotanMessageDigest {
        /**
         * Constructs a new SHA-224 message digest.
         *
         * @throws NoSuchAlgorithmException if SHA-224 is not available
         */
        public SHA224() throws NoSuchAlgorithmException {
            super("SHA-224", 28);
        }
    }

    /**
     * SHA-256 message digest implementation (256-bit output).
     */
    public static final class SHA256 extends BotanMessageDigest {
        /**
         * Constructs a new SHA-256 message digest.
         *
         * @throws NoSuchAlgorithmException if SHA-256 is not available
         */
        public SHA256() throws NoSuchAlgorithmException {
            super("SHA-256", 32);
        }
    }

    /**
     * SHA-384 message digest implementation (384-bit output).
     */
    public static final class SHA384 extends BotanMessageDigest {
        /**
         * Constructs a new SHA-384 message digest.
         *
         * @throws NoSuchAlgorithmException if SHA-384 is not available
         */
        public SHA384() throws NoSuchAlgorithmException {
            super("SHA-384", 48);
        }
    }

    /**
     * SHA-512 message digest implementation (512-bit output).
     */
    public static final class SHA512 extends BotanMessageDigest {
        /**
         * Constructs a new SHA-512 message digest.
         *
         * @throws NoSuchAlgorithmException if SHA-512 is not available
         */
        public SHA512() throws NoSuchAlgorithmException {
            super("SHA-512", 64);
        }
    }

    /**
     * SHA3-224 message digest implementation (224-bit output).
     */
    @SuppressWarnings("typename")
    public static final class SHA3_224 extends BotanMessageDigest {
        /**
         * Constructs a new SHA3-224 message digest.
         *
         * @throws NoSuchAlgorithmException if SHA3-224 is not available
         */
        public SHA3_224() throws NoSuchAlgorithmException {
            super("SHA-3(224)", 28);
        }
    }

    /**
     * SHA3-256 message digest implementation (256-bit output).
     */
    @SuppressWarnings("typename")
    public static final class SHA3_256 extends BotanMessageDigest {
        /**
         * Constructs a new SHA3-256 message digest.
         *
         * @throws NoSuchAlgorithmException if SHA3-256 is not available
         */
        public SHA3_256() throws NoSuchAlgorithmException {
            super("SHA-3(256)", 32);
        }
    }

    /**
     * SHA3-384 message digest implementation (384-bit output).
     */
    @SuppressWarnings("typename")
    public static final class SHA3_384 extends BotanMessageDigest {
        /**
         * Constructs a new SHA3-384 message digest.
         *
         * @throws NoSuchAlgorithmException if SHA3-384 is not available
         */
        public SHA3_384() throws NoSuchAlgorithmException {
            super("SHA-3(384)", 48);
        }
    }

    /**
     * SHA3-512 message digest implementation (512-bit output).
     */
    @SuppressWarnings("typename")
    public static final class SHA3_512 extends BotanMessageDigest {
        /**
         * Constructs a new SHA3-512 message digest.
         *
         * @throws NoSuchAlgorithmException if SHA3-512 is not available
         */
        public SHA3_512() throws NoSuchAlgorithmException {
            super("SHA-3(512)", 64);
        }
    }

    /**
     * Keccak-224 message digest implementation (224-bit output).
     */
    public static final class Keccak224 extends BotanMessageDigest {
        /**
         * Constructs a new Keccak-224 message digest.
         *
         * @throws NoSuchAlgorithmException if Keccak-224 is not available
         */
        public Keccak224() throws NoSuchAlgorithmException {
            super("Keccak-1600(224)", 28);
        }
    }

    /**
     * Keccak-256 message digest implementation (256-bit output).
     */
    public static final class Keccak256 extends BotanMessageDigest {
        /**
         * Constructs a new Keccak-256 message digest.
         *
         * @throws NoSuchAlgorithmException if Keccak-256 is not available
         */
        public Keccak256() throws NoSuchAlgorithmException {
            super("Keccak-1600(256)", 32);
        }
    }

    /**
     * Keccak-384 message digest implementation (384-bit output).
     */
    public static final class Keccak384 extends BotanMessageDigest {
        /**
         * Constructs a new Keccak-384 message digest.
         *
         * @throws NoSuchAlgorithmException if Keccak-384 is not available
         */
        public Keccak384() throws NoSuchAlgorithmException {
            super("Keccak-1600(384)", 48);
        }
    }

    /**
     * Keccak-512 message digest implementation (512-bit output).
     */
    public static final class Keccak512 extends BotanMessageDigest {
        /**
         * Constructs a new Keccak-512 message digest.
         *
         * @throws NoSuchAlgorithmException if Keccak-512 is not available
         */
        public Keccak512() throws NoSuchAlgorithmException {
            super("Keccak-1600(512)", 64);
        }
    }

    /**
     * BLAKE2b-160 message digest implementation (160-bit output).
     */
    public static final class Blake2b160 extends BotanMessageDigest {
        /**
         * Constructs a new BLAKE2b-160 message digest.
         *
         * @throws NoSuchAlgorithmException if BLAKE2b-160 is not available
         */
        public Blake2b160() throws NoSuchAlgorithmException {
            super("Blake2b(160)", 20);
        }
    }

    /**
     * BLAKE2b-256 message digest implementation (256-bit output).
     */
    public static final class Blake2b256 extends BotanMessageDigest {
        /**
         * Constructs a new BLAKE2b-256 message digest.
         *
         * @throws NoSuchAlgorithmException if BLAKE2b-256 is not available
         */
        public Blake2b256() throws NoSuchAlgorithmException {
            super("Blake2b(256)", 32);
        }
    }

    /**
     * BLAKE2b-384 message digest implementation (384-bit output).
     */
    public static final class Blake2b384 extends BotanMessageDigest {
        /**
         * Constructs a new BLAKE2b-384 message digest.
         *
         * @throws NoSuchAlgorithmException if BLAKE2b-384 is not available
         */
        public Blake2b384() throws NoSuchAlgorithmException {
            super("Blake2b(384)", 48);
        }
    }

    /**
     * BLAKE2b-512 message digest implementation (512-bit output).
     */
    public static final class Blake2b512 extends BotanMessageDigest {
        /**
         * Constructs a new BLAKE2b-512 message digest.
         *
         * @throws NoSuchAlgorithmException if BLAKE2b-512 is not available
         */
        public Blake2b512() throws NoSuchAlgorithmException {
            super("Blake2b(512)", 64);
        }
    }

    /**
     * MD4 message digest implementation (128-bit output).
     */
    public static final class MD4 extends BotanMessageDigest {
        /**
         * Constructs a new MD4 message digest.
         *
         * @throws NoSuchAlgorithmException if MD4 is not available
         */
        public MD4() throws NoSuchAlgorithmException {
            super("MD4", 16);
        }
    }

    /**
     * MD5 message digest implementation (128-bit output).
     */
    public static final class MD5 extends BotanMessageDigest {
        /**
         * Constructs a new MD5 message digest.
         *
         * @throws NoSuchAlgorithmException if MD5 is not available
         */
        public MD5() throws NoSuchAlgorithmException {
            super("MD5", 16);
        }
    }

    /**
     * RIPEMD-160 message digest implementation (160-bit output).
     */
    public static final class RipeMd160 extends BotanMessageDigest {
        /**
         * Constructs a new RIPEMD-160 message digest.
         *
         * @throws NoSuchAlgorithmException if RIPEMD-160 is not available
         */
        public RipeMd160() throws NoSuchAlgorithmException {
            super("RIPEMD-160", 20);
        }
    }

}
