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

public final class HexUtils {

    private static final BotanNative NATIVE = Botan.getInstance();

    private HexUtils() {
        // Not meant to be instantiated
    }

    public static byte[] encode(byte[] input) {
        byte[] result = new byte[input.length * 2];
        int err = NATIVE.botan_hex_encode(input, input.length, result, 1);
        if (err != 0) {
            //TODO: throw err
            System.out.println(NATIVE.botan_error_description(err));
        }

        return result;
    }

    public static byte[] decode(byte[] input) {
        byte[] result = new byte[input.length];
        NativeLongByReference length = new NativeLongByReference();

        int err = NATIVE.botan_hex_decode(input, input.length, result, length);
        if (err != 0) {
            //TODO: throw err
            System.out.println(NATIVE.botan_error_description(err));
        }

        return Arrays.copyOfRange(result, 0, length.intValue());
    }

    public static byte[] decode(String input) {
        return decode(input.getBytes());
    }

}
