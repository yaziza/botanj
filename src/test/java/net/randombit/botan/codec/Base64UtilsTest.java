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
    @DisplayName("Test encoding empty string to Base64")
    public void testEncodeWithEmptyInput() {
        final String str = "";
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
    }

    @Test
    @DisplayName("Test encoding string to Base64 without pading")
    public void testEncodeWithoutPadding() {
        final String str = "Lorem ipsum dolor sit amet, consectetur adipiscing eli";
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
    }

    @Test
    @DisplayName("Test encoding string to Base64 with one padding character")
    public void testEncodeOnePadding() {
        final String str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
    }

    @Test
    @DisplayName("Test encoding string to Base64 with two padding character")
    public void testEncodeTwoPadding() {
        final String str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, a";
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
    }

    @Test
    @DisplayName("Test decoding Base64 bytes without padding")
    public void testDecodeWithoutPadding() {
        final String str = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwg";
        final byte[] expected = Base64.getDecoder().decode(str);
        final byte[] actual = Base64Utils.decode(str.getBytes());

        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
    }

    @Test
    @DisplayName("Test decoding Base64 bytes with one padding character")
    public void testDecodeWithOnePadding() {
        final String str = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4=";
        final byte[] expected = Base64.getDecoder().decode(str);
        final byte[] actual = Base64Utils.decode(str.getBytes());

        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
    }

    @Test
    @DisplayName("Test decoding Base64 bytes with two padding character")
    public void testDecodeWithTwoPadding() {
        final String str = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgYQ==";
        final byte[] expected = Base64.getDecoder().decode(str);
        final byte[] actual = Base64Utils.decode(str.getBytes());

        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
    }

    @Test
    @DisplayName("Test encoding then decoding string")
    public void testEncodeThenDecode() {
        final String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
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
