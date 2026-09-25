/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.codec;

import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;
import static net.randombit.botan.jnr.BotanInstance.checkNativeCall;
import static net.randombit.botan.jnr.BotanInstance.singleton;
import static net.randombit.botan.util.BotanUtil.verifyInput;

import java.util.Arrays;
import jnr.ffi.byref.NativeLongByReference;

/** Utility class for hexadecimal encoding and decoding operations. */
public final class HexUtils {

  private static final Character[] ALLOWED_CHARS = {
    'a', 'A', 'b', 'B', 'c', 'C',
    'd', 'D', 'e', 'E', 'f', 'F',
    '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', ' '
  };

  private HexUtils() {
    // Not meant to be instantiated
  }

  /**
   * Performs hex encoding.
   *
   * @param input input
   * @param upperCase output be upper case
   * @return encoded output
   */
  public static byte[] encode(byte[] input, boolean upperCase) {
    // Throwing an exception if the result overflows
    final int resultSize = Math.multiplyExact(input.length, 2);
    final byte[] result = new byte[resultSize];

    final int err = singleton().botan_hex_encode(input, input.length, result, upperCase ? 1 : 0);
    checkNativeCall(err, "botan_hex_encode");

    return result;
  }

  /**
   * Performs hex encoding.
   *
   * @param input input
   * @param upperCase output be upper case
   * @return encoded output {@link String}
   */
  public static String encodeToHexString(byte[] input, boolean upperCase) {
    return new String(encode(input, upperCase));
  }

  /**
   * Performs hex decoding.
   *
   * @param input encoded input
   * @return decoded output
   */
  public static byte[] decode(byte[] input) {
    if (input.length == 0) {
      return EMPTY_BYTE_ARRAY;
    }

    verifyInput(input, Arrays.asList(ALLOWED_CHARS));

    final byte[] result = new byte[input.length];
    final NativeLongByReference length = new NativeLongByReference();

    final int err = singleton().botan_hex_decode(input, input.length, result, length);
    checkNativeCall(err, "botan_hex_decode");

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
