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

public final class Base64Utils {

    private Base64Utils() {
        // Not meant to be instantiated
    }

    /**
     * Performs bas64 encoding.
     *
     * @param input input
     * @return encoded output
     */
    public static byte[] encode(byte[] input) {
        final int outputSize = base64OutputLength(input);

        final byte[] result = new byte[outputSize];
        final NativeLongByReference length = new NativeLongByReference();

        singleton().botan_base64_encode(input, input.length, result, length);

        return result;
    }

    /**
     * Performs bas64 decoding.
     *
     * @param input encoded input
     * @return decoded output
     */
    public static byte[] decode(byte[] input) {
        final byte[] result = new byte[base64InputLength(input)];
        final NativeLongByReference length = new NativeLongByReference();

        singleton().botan_base64_decode(new String(input), input.length, result, length);

        return Arrays.copyOfRange(result, 0, length.intValue());
    }

    /**
     * Performs bas64 decoding.
     *
     * @param input {@link String} input
     * @return decoded output
     */
    public static byte[] decode(String input) {
        return decode(input.getBytes());
    }

    private static int base64OutputLength(byte[] output) {
        int n = output.length;

        // Throwing an exception if the result overflows
        n = Math.multiplyExact(n, 4);
        n = Math.addExact(n, 2);

        return n / 3;
    }

    private static int base64InputLength(byte[] input) {
        int n = input.length;

        return n - (n / 3) + 2;
    }

}
