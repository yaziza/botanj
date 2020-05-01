/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.codec;

import static net.randombit.botan.Botan.singleton;

import java.util.Arrays;

import jnr.ffi.byref.NativeLongByReference;

public final class HexUtils {

    private HexUtils() {
        // Not meant to be instantiated
    }

    /**
     * Performs hex encoding.
     *
     * @param input input
     * @return encoded output
     */
    public static byte[] encode(byte[] input) {
        // Throwing an exception if the result overflows
        final int resultSize = Math.multiplyExact(input.length, 2);
        final byte[] result = new byte[resultSize];

        singleton().botan_hex_encode(input, input.length, result, 1);

        return result;
    }

    /**
     * Performs hex encoding.
     *
     * @param input input
     * @return encoded output {@link String}
     */
    public static String encodeToHexString(byte[] input) {
        return new String(encode(input));
    }

    /**
     * Performs hex decoding.
     *
     * @param input encoded input
     * @return decoded output
     */
    public static byte[] decode(byte[] input) {
        final byte[] result = new byte[input.length];
        final NativeLongByReference length = new NativeLongByReference();

        singleton().botan_hex_decode(input, input.length, result, length);

        return Arrays.copyOfRange(result, 0, length.intValue());
    }

    /**
     * Performs hex decoding.
     *
     * @param input encoded {@link String} input
     * @return decoded output
     */
    public static byte[] decode(String input) {
        return decode(input.getBytes());
    }

}
