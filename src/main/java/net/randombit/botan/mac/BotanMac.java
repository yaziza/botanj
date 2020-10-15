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
import static net.randombit.botan.BotanUtil.checkKeySize;
import static net.randombit.botan.BotanUtil.checkSecretKey;

import javax.crypto.MacSpi;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import jnr.ffi.Pointer;
import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;
import net.randombit.botan.BotanUtil;

public abstract class BotanMac extends MacSpi {

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

    private BotanMac(String name, int size) {
        this.name = name;
        this.size = size;
        this.macRef = new PointerByReference();
    }

    /**
     * Gets the native botan cipher name (e.g. 'CMAC(AES-128)').
     *
     * @param keySize the key size
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

        int err = singleton().botan_mac_init(macRef, getBotanMacName(length), 0);
        checkNativeCall(err, "botan_mac_init");

        BotanUtil.FourParameterFunction<Pointer, NativeLongByReference> getKeySpec = (a, b, c, d) -> {
            return singleton().botan_mac_get_keyspec(a, b, c, d);
        };

        checkKeySize(macRef.getValue(), length, getKeySpec);

        err = singleton().botan_mac_set_key(macRef.getValue(), key.getEncoded(), length);
        checkNativeCall(err, "botan_mac_set_key");
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
    }

    @Override
    protected byte[] engineDoFinal() {
        final byte[] result = new byte[size];
        final int err = singleton().botan_mac_final(macRef.getValue(), result);
        checkNativeCall(err, "botan_mac_final");

        return result;
    }

    @Override
    protected void engineReset() {
        final int err = singleton().botan_mac_clear(macRef.getValue());
        checkNativeCall(err, "botan_mac_clear");
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
