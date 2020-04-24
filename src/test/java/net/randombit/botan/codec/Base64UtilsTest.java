/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.codec;

import org.junit.Assert;
import org.junit.Test;

import java.util.Base64;

public class Base64UtilsTest {

    @Test
    public void testEncode() {
        final String str = "some text";
        final byte[] expected = Base64.getEncoder().encode(str.getBytes());
        final byte[] actual = Base64Utils.encode(str.getBytes());

        Assert.assertArrayEquals("Base64 mismatch with java.util", expected, actual);
    }

    @Test
    public void decode() {
        final String str = "c29tZSBzZWNyZXQ=";
        final byte[] expected = Base64.getDecoder().decode(str);
        final byte[] actual = Base64Utils.decode(str.getBytes());

        Assert.assertArrayEquals("Base64 mismatch with java.util", expected, actual);
    }

    @Test
    public void testDecodeString() {
        final String base64 = "c29tZSBzZWNyZXQ=";
        byte[] expected = Base64.getDecoder().decode(base64);
        byte[] actual = Base64Utils.decode(base64);

        Assert.assertArrayEquals("Hex mismatch with bouncy castle ", expected, actual);
    }

    @Test
    public void testEncodeThenDecode() {
        final String input = "some input";
        final byte[] expected = input.getBytes();
        final byte[] encoded = Base64Utils.encode(input.getBytes());
        final byte[] actual = Base64Utils.decode(encoded);

        Assert.assertArrayEquals("Base64 mismatch with input ", expected, actual);
    }

}
