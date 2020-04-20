/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.digest;

import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;

public class BotanMessageDigest extends MessageDigestSpi {

    /**
     * Holds the name of the hashing algorithm.
     */
    private final String name;

    /**
     * Holds the output size of the message digest in bytes.
     */
    private final int size;

    @Override
    protected int engineGetDigestLength() {
        return size;
    }

    private BotanMessageDigest(String name, int size) {
        this.name = name;
        this.size = size;
    }

    @Override
    protected void engineUpdate(byte input) {

    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {

    }

    @Override
    protected byte[] engineDigest() {
        return new byte[size];
    }

    @Override
    protected void engineReset() {

    }

    // SHA-1 algorithm
    public static final class SHA1 extends BotanMessageDigest {
        public SHA1() {
            super("SHA-1", 20);
        }
    }

    // SHA-2 algorithm
    public static final class SHA224 extends BotanMessageDigest {
        public SHA224() {
            super("SHA-224", 28);
        }
    }

    public static final class SHA256 extends BotanMessageDigest {
        public SHA256() {
            super("SHA-256", 32);
        }
    }

    public static final class SHA384 extends BotanMessageDigest {
        public SHA384() {
            super("SHA-384", 48);
        }
    }

    public static final class SHA512 extends BotanMessageDigest {
        public SHA512() {
            super("SHA-512", 64);
        }
    }

    // SHA-3 algorithm
    @SuppressWarnings("typename")
    public static final class SHA3_224 extends BotanMessageDigest {
        public SHA3_224() {
            super("SHA3-224", 28);
        }
    }

    @SuppressWarnings("typename")
    public static final class SHA3_256 extends BotanMessageDigest {
        public SHA3_256() {
            super("SHA3-256", 32);
        }
    }

    @SuppressWarnings("typename")
    public static final class SHA3_384 extends BotanMessageDigest {
        public SHA3_384() {
            super("SHA3-384", 48);
        }
    }

    @SuppressWarnings("typename")
    public static final class SHA3_512 extends BotanMessageDigest {
        public SHA3_512() {
            super("SHA3-512", 64);
        }
    }

    //Keccak algorithm
    public static final class Keccak224 extends BotanMessageDigest {
        public Keccak224() {
            super("KECCAK-224", 28);
        }
    }

    public static final class Keccak256 extends BotanMessageDigest {
        public Keccak256() {
            super("KECCAK-256", 32);
        }
    }

    public static final class Keccak384 extends BotanMessageDigest {
        public Keccak384() {
            super("KECCAK-384", 48);
        }
    }

    public static final class Keccak512 extends BotanMessageDigest {
        public Keccak512() {
            super("KECCAK-512", 64);
        }
    }

    // Blake2b algorithm
    public static final class Blake2b160 extends BotanMessageDigest {
        public Blake2b160() {
            super("BLAKE2B-160", 20);
        }
    }

    public static final class Blake2b256 extends BotanMessageDigest {
        public Blake2b256() {
            super("BLAKE2B-256", 32);
        }
    }

    public static final class Blake2b384 extends BotanMessageDigest {
        public Blake2b384() {
            super("BLAKE2B-384", 48);
        }
    }

    public static final class Blake2b512 extends BotanMessageDigest {
        public Blake2b512() {
            super("BLAKE2B-512", 64);
        }
    }

    // RIPEMD-160 algorithm
    public static final class RipeMd160 extends BotanMessageDigest {
        public RipeMd160() {
            super("RIPEMD-160", 20);
        }
    }

}
