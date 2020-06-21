/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.codec;

import static net.randombit.botan.Botan.checkNativeCall;
import static net.randombit.botan.Botan.singleton;
import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;

import java.util.Arrays;
import java.util.List;

import jnr.ffi.byref.NativeLongByReference;

public final class Base64Utils {

    private static final Character[] ALLOWED_CHARS = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '='
    };

    private static final List<Character> ALLOWED_CHARS_LIST = Arrays.asList(ALLOWED_CHARS);

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

        final int err = singleton().botan_base64_encode(input, input.length, result, length);
        checkNativeCall(err, "botan_base64_encode");

        return result;
    }

    /**
     * Performs bas64 decoding.
     *
     * @param input encoded input
     * @return decoded output
     */
    public static byte[] decode(byte[] input) {
        if (input.length == 0) {
            return EMPTY_BYTE_ARRAY;
        }

        verifyInput(input);

        final byte[] result = new byte[base64InputLength(input)];
        final NativeLongByReference length = new NativeLongByReference();

        final int err = singleton().botan_base64_decode(new String(input), input.length, result, length);
        checkNativeCall(err, "botan_base64_decode");

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

    private static void verifyInput(byte[] input) {
        String inputStr = new String(input);

        for (char chr : inputStr.toCharArray()) {
            if (!ALLOWED_CHARS_LIST.contains(chr)) {
                throw new IllegalArgumentException("Cannot decode malformed input!");
            }
        }
    }

}
