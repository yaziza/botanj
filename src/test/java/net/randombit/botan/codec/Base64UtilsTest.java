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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Botan Base64 util tests")
public class Base64UtilsTest {

    private static final Logger LOG = LogManager.getLogger(Base64UtilsTest.class.getSimpleName());

    @Test
    @DisplayName("Test encoding empty string to Base64")
    public void testEncodeWithEmptyInput() {
        LOG.info("=== Test: Encoding empty string to Base64 ===");
        final String str = "";
        LOG.info("Input: empty string");
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        LOG.info("Expected (java.util.Base64): {} bytes", expected.length);
        LOG.info("Actual (Botan): {} bytes", actual.length);
        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
        LOG.info("SUCCESS: Empty string encoding matches java.util.Base64");
    }

    @Test
    @DisplayName("Test encoding string to Base64 without pading")
    public void testEncodeWithoutPadding() {
        LOG.info("=== Test: Encoding string to Base64 without padding ===");
        final String str = "Lorem ipsum dolor sit amet, consectetur adipiscing eli";
        LOG.info("Input length: {} characters (no padding needed)", str.length());
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        LOG.info("Expected: {} bytes", expected.length);
        LOG.info("Actual: {} bytes", actual.length);
        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
        LOG.info("SUCCESS: Encoding without padding matches java.util.Base64");
    }

    @Test
    @DisplayName("Test encoding string to Base64 with one padding character")
    public void testEncodeOnePadding() {
        LOG.info("=== Test: Encoding string to Base64 with one padding character ===");
        final String str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        LOG.info("Input length: {} characters (one padding char needed)", str.length());
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        LOG.info("Expected: {} bytes", expected.length);
        LOG.info("Actual: {} bytes", actual.length);
        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
        LOG.info("SUCCESS: Encoding with one padding matches java.util.Base64");
    }

    @Test
    @DisplayName("Test encoding string to Base64 with two padding character")
    public void testEncodeTwoPadding() {
        LOG.info("=== Test: Encoding string to Base64 with two padding characters ===");
        final String str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, a";
        LOG.info("Input length: {} characters (two padding chars needed)", str.length());
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        LOG.info("Expected: {} bytes", expected.length);
        LOG.info("Actual: {} bytes", actual.length);
        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
        LOG.info("SUCCESS: Encoding with two padding matches java.util.Base64");
    }

    @Test
    @DisplayName("Test decoding Base64 bytes without padding")
    public void testDecodeWithoutPadding() {
        LOG.info("=== Test: Decoding Base64 bytes without padding ===");
        final String str = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwg";
        LOG.info("Input (Base64): {} characters (no padding)", str.length());
        final byte[] expected = Base64.getDecoder().decode(str);
        final byte[] actual = Base64Utils.decode(str.getBytes());

        LOG.info("Expected: {} bytes", expected.length);
        LOG.info("Actual: {} bytes", actual.length);
        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
        LOG.info("SUCCESS: Decoding without padding matches java.util.Base64");
    }

    @Test
    @DisplayName("Test decoding Base64 bytes with one padding character")
    public void testDecodeWithOnePadding() {
        LOG.info("=== Test: Decoding Base64 bytes with one padding character ===");
        final String str = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4=";
        LOG.info("Input (Base64): {} characters (one padding '=')", str.length());
        final byte[] expected = Base64.getDecoder().decode(str);
        final byte[] actual = Base64Utils.decode(str.getBytes());

        LOG.info("Expected: {} bytes", expected.length);
        LOG.info("Actual: {} bytes", actual.length);
        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
        LOG.info("SUCCESS: Decoding with one padding matches java.util.Base64");
    }

    @Test
    @DisplayName("Test decoding Base64 bytes with two padding character")
    public void testDecodeWithTwoPadding() {
        LOG.info("=== Test: Decoding Base64 bytes with two padding characters ===");
        final String str = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgYQ==";
        LOG.info("Input (Base64): {} characters (two padding '==')", str.length());
        final byte[] expected = Base64.getDecoder().decode(str);
        final byte[] actual = Base64Utils.decode(str.getBytes());

        LOG.info("Expected: {} bytes", expected.length);
        LOG.info("Actual: {} bytes", actual.length);
        assertArrayEquals(expected, actual, "Base64 mismatch with java.util");
        LOG.info("SUCCESS: Decoding with two padding matches java.util.Base64");
    }

    @Test
    @DisplayName("Test encoding then decoding string")
    public void testEncodeThenDecode() {
        LOG.info("=== Test: Encoding then decoding string ===");
        final String input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";
        LOG.info("Original input: '{}...' ({} chars)", input.substring(0, 20), input.length());
        final byte[] expected = input.getBytes();
        final byte[] encoded = Base64Utils.encode(input.getBytes());
        LOG.info("Encoded to: {} bytes", encoded.length);
        final byte[] actual = Base64Utils.decode(encoded);
        LOG.info("Decoded to: {} bytes", actual.length);

        assertArrayEquals(expected, actual, "Base64 mismatch with input");
        LOG.info("SUCCESS: Round-trip encoding/decoding successful");
    }

    @Test
    @DisplayName("Test encoding malformed input")
    public void testDecodeMalformedInput() {
        LOG.info("=== Test: Decoding malformed input ===");
        final String input = "some malformed input";
        LOG.info("Testing malformed input: '{}'", input);

        final Exception exception = assertThrows(IllegalArgumentException.class, () -> Base64Utils.decode(input));

        assertEquals("Cannot decode malformed input!", exception.getMessage());
        LOG.info("SUCCESS: Properly rejected malformed input with correct error message");
    }

    @Test
    @DisplayName("Test decoding input with invalid length (not multiple of 4)")
    public void testDecodeInvalidLength() {
        LOG.info("=== Test: Decoding input with invalid length ===");
        // Create valid Base64 characters but with length not divisible by 4
        final String input = "ABC"; // length = 3, not multiple of 4
        LOG.info("Testing input with length {}, which is not a multiple of 4", input.length());

        final Exception exception = assertThrows(ArithmeticException.class, () -> Base64Utils.decode(input));

        assertEquals("Input length is not a multiple of 4", exception.getMessage());
        LOG.info("SUCCESS: Properly rejected input with invalid length");
    }

}
