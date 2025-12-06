/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.rng;

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;
import net.randombit.botan.jnr.BotanInstance;

import java.lang.ref.Cleaner;
import java.security.SecureRandomSpi;

import static net.randombit.botan.jnr.BotanInstance.checkNativeCall;
import static net.randombit.botan.jnr.BotanInstance.singleton;
import static net.randombit.botan.util.BotanUtil.isNullOrEmpty;

/**
 * Botan-based implementation of {@link SecureRandomSpi}.
 *
 * <p>This class provides cryptographically secure pseudo-random number generation (CSPRNG)
 * using the Botan cryptographic library's native random number generators. It integrates
 * seamlessly with Java's {@link java.security.SecureRandom} API while leveraging Botan's
 * randomness sources.</p>
 *
 * <h2>Supported RNG Types</h2>
 *
 * <p>Botanj supports multiple RNG types through Botan:</p>
 * <ul>
 *   <li><b>system</b> - System RNG (default): Uses OS-provided entropy sources
 *       (e.g., /dev/urandom on Unix, CryptGenRandom on Windows)</li>
 *   <li><b>user</b> - User-space RNG: ChaCha20-based CSPRNG seeded from system RNG</li>
 *   <li><b>user-threadsafe</b> - Thread-safe user-space RNG: Same as user but with
 *       internal locking for concurrent access</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 *
 * <pre>{@code
 * // Get default RNG (system RNG)
 * SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");
 * byte[] randomBytes = new byte[32];
 * rng.nextBytes(randomBytes);
 *
 * // Get specific RNG type
 * SecureRandom userRng = SecureRandom.getInstance("Botan-User", "Botan");
 * userRng.nextBytes(randomBytes);
 *
 * // Add custom entropy
 * byte[] entropy = getEntropyFromSensor();
 * userRng.setSeed(entropy);
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 *
 * <p>Thread safety depends on the RNG type:</p>
 * <ul>
 *   <li><b>system RNG</b>: Thread-safe (backed by OS)</li>
 *   <li><b>user RNG</b>: NOT thread-safe - use separate instances per thread</li>
 *   <li><b>user-threadsafe RNG</b>: Thread-safe with internal locking</li>
 * </ul>
 *
 * <h2>Resource Management</h2>
 *
 * <p>Native RNG resources are automatically cleaned up via Java's {@link Cleaner} API:
 * <ul>
 *   <li>RNG objects are destroyed when the Java object is garbage collected</li>
 *   <li>Cleaner ensures cleanup even if exceptions occur</li>
 * </ul>
 *
 * <h2>Security Considerations</h2>
 *
 * <ul>
 *   <li><b>Cryptographically Secure</b>: All RNG types are suitable for cryptographic use</li>
 *   <li><b>Automatic Seeding</b>: System RNG automatically seeds user-space RNGs</li>
 *   <li><b>Entropy Addition</b>: {@link #engineSetSeed(byte[])} adds entropy without replacing existing state</li>
 *   <li><b>No Prediction</b>: Internal state cannot be predicted from outputs</li>
 * </ul>
 *
 * @author Yasser Aziza
 * @see java.security.SecureRandom
 * @see java.security.SecureRandomSpi
 * @since 0.1.0
 */
public abstract class BotanSecureRandom extends SecureRandomSpi {

    private static final Cleaner CLEANER = Cleaner.create();
    private static final long serialVersionUID = 1L;

    /**
     * Reference to the native Botan RNG object.
     */
    protected final PointerByReference rngRef;

    /**
     * Cleaner registration for automatic cleanup.
     */
    private Cleaner.Cleanable cleanable;

    /**
     * Constructs a new BotanSecureRandom with the specified RNG type.
     *
     * @param rngType the RNG type name ("system", "user", "user-threadsafe", or null for default)
     */
    protected BotanSecureRandom(String rngType) {
        BotanInstance.checkAvailability();
        this.rngRef = new PointerByReference();

        int err = singleton().botan_rng_init(rngRef, rngType);
        checkNativeCall(err, "botan_rng_init");

        // Register cleaner for automatic resource cleanup
        cleanable = CLEANER.register(this, new BotanRngCleanupAction(rngRef.getValue()));
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
        if (seed == null) {
            throw new NullPointerException("seed must not be null");
        }
        if (seed.length == 0) {
            return;
        }

        int err = singleton().botan_rng_add_entropy(rngRef.getValue(), seed, seed.length);
        checkNativeCall(err, "botan_rng_add_entropy");
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        if (bytes == null) {
            throw new NullPointerException("bytes must not be null");
        }
        if (bytes.length == 0) {
            return;
        }

        int err = singleton().botan_rng_get(rngRef.getValue(), bytes, bytes.length);
        checkNativeCall(err, "botan_rng_get");
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        if (numBytes < 0) {
            throw new IllegalArgumentException("numBytes must be non-negative");
        }

        byte[] seed = new byte[numBytes];
        if (numBytes > 0) {
            engineNextBytes(seed);
        }
        return seed;
    }

    /**
     * Reseeds this RNG with the specified number of bits from the system RNG.
     *
     * @param bits number of bits to reseed with (typically 256 or 384)
     */
    protected void reseed(long bits) {
        int err = singleton().botan_rng_reseed(rngRef.getValue(), bits);
        checkNativeCall(err, "botan_rng_reseed");
    }

    /**
     * Cleanup action for native RNG resources.
     */
    private record BotanRngCleanupAction(Pointer rngPointer) implements Runnable {

        @Override
        public void run() {
            if (rngPointer != null) {
                singleton().botan_rng_destroy(rngPointer);
            }
        }
    }

    /**
     * System RNG implementation.
     *
     * <p>Uses the operating system's entropy source directly. This is the most
     * secure option as it bypasses any userspace buffering and gets randomness
     * directly from the OS.</p>
     *
     * <p>Thread-safe: Yes (backed by OS)</p>
     */
    public static final class SystemRng extends BotanSecureRandom {

        /**
         * Constructs a new System RNG.
         */
        public SystemRng() {
            super("system");
        }
    }

    /**
     * User-space RNG implementation.
     *
     * <p>ChaCha20-based CSPRNG that is automatically seeded from the system RNG.
     * Faster than system RNG for generating large amounts of random data, while
     * maintaining cryptographic security.</p>
     *
     * <p>Thread-safe: No (use separate instances per thread or use UserThreadsafeRng)</p>
     */
    public static final class UserRng extends BotanSecureRandom {

        /**
         * Constructs a new User RNG.
         */
        public UserRng() {
            super("user");
        }
    }

    /**
     * Thread-safe user-space RNG implementation.
     *
     * <p>Same as UserRng but with internal locking to allow safe concurrent access
     * from multiple threads. Slight performance overhead compared to UserRng due
     * to synchronization.</p>
     *
     * <p>Thread-safe: Yes</p>
     */
    public static final class UserThreadsafeRng extends BotanSecureRandom {

        /**
         * Constructs a new Thread-safe User RNG.
         */
        public UserThreadsafeRng() {
            super("user-threadsafe");
        }
    }
}
