/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.codec;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class HexUtilsTest {

    @Test
    public void testEncode() {
        final String input = "some input";

        final byte[] expected = Hex.encode(input.getBytes());
        final byte[] actual = HexUtils.encode(input.getBytes());

        Assert.assertArrayEquals("Hex mismatch with bouncy castle ", expected, actual);
    }

    @Test
    public void testDecode() {
        final String expected = "some input";
        final byte[] input = Hex.encode(expected.getBytes());
        final byte[] actual = HexUtils.decode(input);

        Assert.assertArrayEquals("Hex mismatch with bouncy castle ", expected.getBytes(), actual);
    }

    @Test
    public void testDecodeString() {
        final String upperCase = "01 03 05 07 09 0B 0D 0F";
        final String lowerCase = "01 03 05 07 09 0b 0d 0f";

        Assert.assertArrayEquals("Hex mismatch with bouncy castle ", Hex.decode(upperCase),
                HexUtils.decode(upperCase));

        Assert.assertArrayEquals("Hex mismatch with bouncy castle ", Hex.decode(lowerCase),
                HexUtils.decode(lowerCase));
    }

    @Test
    public void testEncodeThenDecode() {
        final String input = "some input";
        final byte[] encoded = HexUtils.encode(input.getBytes());
        final byte[] decoded = HexUtils.decode(encoded);

        Assert.assertArrayEquals("Hex mismatch with input ", input.getBytes(), decoded);
    }

}

