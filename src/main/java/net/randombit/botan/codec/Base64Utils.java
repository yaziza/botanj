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
import net.randombit.botan.Botan;
import net.randombit.botan.BotanNative;

import java.util.Arrays;

public final class Base64Utils {

    private static final BotanNative NATIVE = Botan.getInstance();

    private Base64Utils() {
        // Not meant to be instantiated
    }

    public static byte[] encode(byte[] input) {
        int outputSize = base64OutputLength(input);

        final byte[] result = new byte[outputSize];
        final NativeLongByReference length = new NativeLongByReference();

        int err = NATIVE.botan_base64_encode(input, input.length, result, length);
        if (err != 0) {
            //TODO: throw err
            System.out.println(NATIVE.botan_error_description(err));
        }

        return result;
    }

    public static byte[] decode(byte[] input) {
        final byte[] result = new byte[base64InputLength(input)];
        final NativeLongByReference length = new NativeLongByReference();

        int err = NATIVE.botan_base64_decode(new String(input), input.length, result, length);
        if (err != 0) {
            //TODO: throw err
            System.out.println(NATIVE.botan_error_description(err));
        }

        return Arrays.copyOfRange(result, 0, length.intValue());
    }

    public static byte[] decode(String input) {
        return decode(input.getBytes());
    }

    private static int base64OutputLength(byte[] output) {
        int n = output.length;

        return (n * 4 + 2) / 3;
    }

    private static int base64InputLength(byte[] input) {
        int n = input.length;

        return n - (n / 3) + 2;
    }

}
