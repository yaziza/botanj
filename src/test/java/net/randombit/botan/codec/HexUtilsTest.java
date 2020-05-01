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
        final String upperCase = "01 03 05 07 09 0B 0D 0F";
        final String lowerCase = "01 03 05 07 09 0b 0d 0f";

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

