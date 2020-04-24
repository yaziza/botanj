/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.mac;

import jnr.ffi.byref.PointerByReference;

import javax.crypto.MacSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import static net.randombit.botan.Botan.singleton;

public class BotanMac extends MacSpi {

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

    @Override
    protected int engineGetMacLength() {
        return size;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        int err = singleton().botan_mac_init(macRef, name, 0);
        if (err != 0) {
            String msg = singleton().botan_error_description(err);
            throw new InvalidAlgorithmParameterException(msg);
        }

        err = singleton().botan_mac_set_key(macRef.getValue(), key.getEncoded(),
                key.getEncoded().length);
        if (err != 0) {
            String msg = singleton().botan_error_description(err);
            throw new InvalidKeyException(msg);
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        singleByte[0] = input;

        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        final byte[] bytes = Arrays.copyOfRange(input, offset, input.length);

        singleton().botan_mac_update(macRef.getValue(), bytes, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        final byte[] result = new byte[size];
        singleton().botan_mac_final(macRef.getValue(), result);

        return result;
    }

    @Override
    protected void engineReset() {
        singleton().botan_mac_clear(macRef.getValue());
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
