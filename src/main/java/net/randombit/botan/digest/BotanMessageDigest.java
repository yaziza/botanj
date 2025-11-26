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

import jnr.ffi.Pointer;
import jnr.ffi.byref.PointerByReference;

public class BotanMessageDigest extends MessageDigestSpi implements Cloneable {

    /**
     * Shared Cleaner instance for all BotanMessageDigest instances.
     */
    private static final Cleaner CLEANER = Cleaner.create();

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

    // SHA-1 algorithm
    public static final class SHA1 extends BotanMessageDigest {
        public SHA1() throws NoSuchAlgorithmException {
            super("SHA-1", 20);
        }
    }

    // SHA-2 algorithm
    public static final class SHA224 extends BotanMessageDigest {
        public SHA224() throws NoSuchAlgorithmException {
            super("SHA-224", 28);
        }
    }

    public static final class SHA256 extends BotanMessageDigest {
        public SHA256() throws NoSuchAlgorithmException {
            super("SHA-256", 32);
        }
    }

    public static final class SHA384 extends BotanMessageDigest {
        public SHA384() throws NoSuchAlgorithmException {
            super("SHA-384", 48);
        }
    }

    public static final class SHA512 extends BotanMessageDigest {
        public SHA512() throws NoSuchAlgorithmException {
            super("SHA-512", 64);
        }
    }

    // SHA-3 algorithm
    @SuppressWarnings("typename")
    public static final class SHA3_224 extends BotanMessageDigest {
        public SHA3_224() throws NoSuchAlgorithmException {
            super("SHA-3(224)", 28);
        }
    }

    @SuppressWarnings("typename")
    public static final class SHA3_256 extends BotanMessageDigest {
        public SHA3_256() throws NoSuchAlgorithmException {
            super("SHA-3(256)", 32);
        }
    }

    @SuppressWarnings("typename")
    public static final class SHA3_384 extends BotanMessageDigest {
        public SHA3_384() throws NoSuchAlgorithmException {
            super("SHA-3(384)", 48);
        }
    }

    @SuppressWarnings("typename")
    public static final class SHA3_512 extends BotanMessageDigest {
        public SHA3_512() throws NoSuchAlgorithmException {
            super("SHA-3(512)", 64);
        }
    }

    //Keccak algorithm
    public static final class Keccak224 extends BotanMessageDigest {
        public Keccak224() throws NoSuchAlgorithmException {
            super("Keccak-1600(224)", 28);
        }
    }

    public static final class Keccak256 extends BotanMessageDigest {
        public Keccak256() throws NoSuchAlgorithmException {
            super("Keccak-1600(256)", 32);
        }
    }

    public static final class Keccak384 extends BotanMessageDigest {
        public Keccak384() throws NoSuchAlgorithmException {
            super("Keccak-1600(384)", 48);
        }
    }

    public static final class Keccak512 extends BotanMessageDigest {
        public Keccak512() throws NoSuchAlgorithmException {
            super("Keccak-1600(512)", 64);
        }
    }

    // Blake2b algorithm
    public static final class Blake2b160 extends BotanMessageDigest {
        public Blake2b160() throws NoSuchAlgorithmException {
            super("Blake2b(160)", 20);
        }
    }

    public static final class Blake2b256 extends BotanMessageDigest {
        public Blake2b256() throws NoSuchAlgorithmException {
            super("Blake2b(256)", 32);
        }
    }

    public static final class Blake2b384 extends BotanMessageDigest {
        public Blake2b384() throws NoSuchAlgorithmException {
            super("Blake2b(384)", 48);
        }
    }

    public static final class Blake2b512 extends BotanMessageDigest {
        public Blake2b512() throws NoSuchAlgorithmException {
            super("Blake2b(512)", 64);
        }
    }

    // MD algorithms
    public static final class MD4 extends BotanMessageDigest {
        public MD4() throws NoSuchAlgorithmException {
            super("MD4", 16);
        }
    }

    public static final class MD5 extends BotanMessageDigest {
        public MD5() throws NoSuchAlgorithmException {
            super("MD5", 16);
        }
    }

    public static final class RipeMd160 extends BotanMessageDigest {
        public RipeMd160() throws NoSuchAlgorithmException {
            super("RIPEMD-160", 20);
        }
    }

}
