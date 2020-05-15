/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.codec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Botan Base64 util tests")
public class Base64UtilsTest {

    @Test
    @DisplayName("Test encoding string to Base64")
    public void testEncode() {
        final String str = "some text";
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
    }

    @Test
    @DisplayName("Test decoding Base64 bytes")
    public void decode() {
        final String str = "c29tZSBzZWNyZXQ=";
        final byte[] expected = Base64.getDecoder().decode(str);
        final byte[] actual = Base64Utils.decode(str.getBytes());

        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
    }

    @Test
    @DisplayName("Test decoding Base64 string")
    public void testDecodeString() {
        final String base64 = "c29tZSBzZWNyZXQ=";
        byte[] expected = Base64.getDecoder().decode(base64);
        byte[] actual = Base64Utils.decode(base64);

        assertArrayEquals(expected, actual, "Hex mismatch with Bouncy Castle");
    }

    @Test
    @DisplayName("Test encoding then decoding string")
    public void testEncodeThenDecode() {
        final String input = "some input";
        final byte[] expected = input.getBytes();
        final byte[] encoded = Base64Utils.encode(input.getBytes());
        final byte[] actual = Base64Utils.decode(encoded);

        assertArrayEquals(expected, actual, "Base64 mismatch with input");
    }

    @Test
    @DisplayName("Test encoding malformed input")
    public void testDecodeMalformedInput() {
        final String input = "some malformed input";

        final Exception exception = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(input));

        assertEquals("Cannot decode malformed input!", exception.getMessage());
    }

}
