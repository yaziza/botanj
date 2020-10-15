/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza  initial implementation
 */

package net.randombit.botan;

import static net.randombit.botan.BotanInstance.checkNativeCall;

import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.List;

import jnr.ffi.Pointer;
import jnr.ffi.byref.NativeLongByReference;

public final class BotanUtil {

    private BotanUtil() {
        // Not meant to be instantiated
    }

    /**
     * Verifies input contains only allowed chars
     *
     * @param input        encoded input
     * @param allowedChars allowed Character list
     * @throws IllegalArgumentException
     */
    public static void verifyInput(byte[] input, List<Character> allowedChars) {
        final String inputStr = new String(input);

        for (char chr : inputStr.toCharArray()) {
            if (!allowedChars.contains(chr)) {
                throw new IllegalArgumentException("Cannot decode malformed input!");
            }
        }
    }

    /**
     * Checks the key type and content not null.
     *
     * @param key
     * @return byte[] encoded key
     * @throws InvalidKeyException
     */
    public static byte[] checkSecretKey(Key key) throws InvalidKeyException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Only SecretKey is supported");
        }

        if (!"RAW".equalsIgnoreCase(key.getFormat())) {
            throw new InvalidKeyException("Only raw format key is supported");
        }

        final byte[] encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new InvalidKeyException("key.getEncoded() == null");
        }

        return encodedKey;
    }

    /**
     * Checks whether the provided key size is valid.
     *
     * @param ptr        the botan native reference
     * @param keySize    the provided key size
     * @param getKeySpec the botan reference key spec method
     * @throws InvalidKeyException
     */
    public static void checkKeySize(Pointer ptr, int keySize, FourParameterFunction getKeySpec)
            throws InvalidKeyException {
        final NativeLongByReference minimumLength = new NativeLongByReference();
        final NativeLongByReference maximumLength = new NativeLongByReference();
        final NativeLongByReference lengthModulo = new NativeLongByReference();

        final int err = getKeySpec.apply(ptr, minimumLength, maximumLength, lengthModulo);
        checkNativeCall(err, "botan_get_keyspec");

        if (keySize < minimumLength.intValue()) {
            throw new InvalidKeyException("key.getEncoded() < minimum key length: " + minimumLength.intValue());
        }

        if (keySize > maximumLength.intValue()) {
            throw new InvalidKeyException("key.getEncoded() > maximum key length: " + maximumLength.intValue());
        }

        if (keySize % lengthModulo.intValue() != 0) {
            throw new InvalidKeyException("key.getEncoded() not multiple of key length modulo: "
                    + lengthModulo.intValue());
        }
    }

    public static boolean isNullOrEmpty(byte[] value) {
        return value == null || value.length == 0;
    }

    @FunctionalInterface
    public interface FourParameterFunction<T, U> {
        int apply(T t, U u, U v, U w);
    }

}
