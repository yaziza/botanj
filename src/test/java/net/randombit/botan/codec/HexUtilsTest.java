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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.bouncycastle.util.encoders.Hex;

@DisplayName("Botan Hex encoding tests")
public class HexUtilsTest {

    @Test
    @DisplayName("Test encoding bytes against Bouncy Castle")
    public void testEncode() {
        final String input = "some input";

        final byte[] expected = Hex.encode(input.getBytes());
        final byte[] actual = HexUtils.encode(input.getBytes());

        assertArrayEquals(expected, actual, "Hex mismatch with Bouncy Castle ");
    }

    @Test
    @DisplayName("Test malformed input")
    public void testMalformedInput() {
        final String input = "some malformed input";

        Exception exception = assertThrows(IllegalArgumentException.class, () -> HexUtils.decode(input));
        assertEquals("Cannot decode malformed input!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () -> HexUtils.decode(input.getBytes()));
        assertEquals("Cannot decode malformed input!", exception.getMessage());
    }

    @Test
    @DisplayName("Test decoding bytes against Bouncy Castle")
    public void testDecode() {
        final String expected = "some input";
        final byte[] input = Hex.encode(expected.getBytes());
        final byte[] actual = HexUtils.decode(input);

        assertArrayEquals(expected.getBytes(), actual, "Hex mismatch with Bouncy Castle");
    }

    @Test
    @DisplayName("Test encoding string against Bouncy Castle")
    public void testDecodeString() {
        final String upperCase = "01 23 45 67 89 AB CD EF";
        final String lowerCase = "01 23 45 67 89 ab cd ef";

        assertArrayEquals(Hex.decode(upperCase), HexUtils.decode(upperCase), "Hex mismatch with Bouncy Castle");
        assertArrayEquals(Hex.decode(lowerCase), HexUtils.decode(lowerCase), "Hex mismatch with Bouncy Castle");
    }

    @Test
    @DisplayName("Test encoding then decoding string")
    public void testEncodeThenDecode() {
        final String input = "some input";
        final byte[] encoded = HexUtils.encode(input.getBytes());
        final byte[] decoded = HexUtils.decode(encoded);

        assertArrayEquals(input.getBytes(), decoded, "Hex mismatch with input");
    }

}

