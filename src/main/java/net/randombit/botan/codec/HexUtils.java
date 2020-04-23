/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.codec;

import jnr.ffi.byref.NativeLongByReference;

import java.util.Arrays;

import static net.randombit.botan.BotanProvider.NATIVE;

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
        byte[] result = new byte[input.length * 2];

        NATIVE.botan_hex_encode(input, input.length, result, 1);

        return result;
    }

    /**
     * Performs hex decoding.
     *
     * @param input encoded input
     * @return decoded output
     */
    public static byte[] decode(byte[] input) {
        byte[] result = new byte[input.length];
        NativeLongByReference length = new NativeLongByReference();

        NATIVE.botan_hex_decode(input, input.length, result, length);

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
