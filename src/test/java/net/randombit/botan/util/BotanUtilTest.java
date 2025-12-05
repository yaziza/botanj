/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.util;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for BotanUtil class to improve coverage.
 */
class BotanUtilTest {

    @Test
    void testIsNullOrEmptyWithNull() {
        // Test null array
        assertTrue(BotanUtil.isNullOrEmpty(null),
                "isNullOrEmpty should return true for null array");
    }

    @Test
    void testIsNullOrEmptyWithEmptyArray() {
        // Test empty array
        assertTrue(BotanUtil.isNullOrEmpty(new byte[0]),
                "isNullOrEmpty should return true for empty array");
    }

    @Test
    void testIsNullOrEmptyWithNonEmptyArray() {
        // Test non-empty array
        assertFalse(BotanUtil.isNullOrEmpty(new byte[]{1, 2, 3}),
                "isNullOrEmpty should return false for non-empty array");
    }

    @Test
    void testVerifyInputWithValidChars() {
        // Test input with only allowed characters
        List<Character> allowed = Arrays.asList('a', 'b', 'c');
        byte[] input = "abc".getBytes();

        assertDoesNotThrow(() -> BotanUtil.verifyInput(input, allowed),
                "verifyInput should not throw for valid input");
    }

    @Test
    void testVerifyInputWithInvalidChars() {
        // Test input with disallowed characters
        List<Character> allowed = Arrays.asList('a', 'b', 'c');
        byte[] input = "abcd".getBytes(); // 'd' is not allowed

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> BotanUtil.verifyInput(input, allowed),
                "verifyInput should throw for invalid input");

        assertEquals("Cannot decode malformed input!", exception.getMessage());
    }

    @Test
    void testCheckSecretKeyWithValidKey() throws InvalidKeyException {
        // Test with valid SecretKey
        byte[] keyBytes = new byte[16];
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        byte[] result = BotanUtil.checkSecretKey(key);
        assertNotNull(result, "checkSecretKey should return non-null for valid key");
        assertArrayEquals(keyBytes, result, "Returned key bytes should match input");
    }

    @Test
    void testCheckSecretKeyWithNonSecretKey() {
        // Test with non-SecretKey (PublicKey)
        Key key = new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "RSA";
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };

        InvalidKeyException exception = assertThrows(InvalidKeyException.class,
                () -> BotanUtil.checkSecretKey(key),
                "checkSecretKey should throw for non-SecretKey");

        assertEquals("Only SecretKey is supported", exception.getMessage());
    }

    @Test
    void testCheckSecretKeyWithNonRawFormat() {
        // Test with SecretKey that doesn't have RAW format
        SecretKey key = new SecretKey() {
            @Override
            public String getAlgorithm() {
                return "AES";
            }

            @Override
            public String getFormat() {
                return "X.509"; // Not RAW
            }

            @Override
            public byte[] getEncoded() {
                return new byte[16];
            }
        };

        InvalidKeyException exception = assertThrows(InvalidKeyException.class,
                () -> BotanUtil.checkSecretKey(key),
                "checkSecretKey should throw for non-RAW format");

        assertEquals("Only raw format key is supported", exception.getMessage());
    }

    @Test
    void testCheckSecretKeyWithNullEncoded() {
        // Test with SecretKey that returns null from getEncoded()
        SecretKey key = new SecretKey() {
            @Override
            public String getAlgorithm() {
                return "AES";
            }

            @Override
            public String getFormat() {
                return "RAW";
            }

            @Override
            public byte[] getEncoded() {
                return null; // Null encoded key
            }
        };

        InvalidKeyException exception = assertThrows(InvalidKeyException.class,
                () -> BotanUtil.checkSecretKey(key),
                "checkSecretKey should throw for null encoded key");

        assertEquals("key.getEncoded() == null", exception.getMessage());
    }

    @Test
    void testVerifyInputWithEmptyInput() {
        // Test with empty input
        List<Character> allowed = Arrays.asList('a', 'b', 'c');
        byte[] input = "".getBytes();

        assertDoesNotThrow(() -> BotanUtil.verifyInput(input, allowed),
                "verifyInput should not throw for empty input");
    }

    @Test
    void testVerifyInputWithAllAllowedChars() {
        // Test input that contains all allowed characters
        List<Character> allowed = Arrays.asList('a', 'b', 'c');
        byte[] input = "abcabcabc".getBytes();

        assertDoesNotThrow(() -> BotanUtil.verifyInput(input, allowed),
                "verifyInput should not throw when all chars are allowed");
    }

    @Test
    void testVerifyInputWithSpecialCharacters() {
        // Test with special characters
        List<Character> allowed = Arrays.asList('a', 'b', 'c', ' ', '\n');
        byte[] input = "abc abc\n".getBytes();

        assertDoesNotThrow(() -> BotanUtil.verifyInput(input, allowed),
                "verifyInput should not throw for allowed special chars");
    }

    @Test
    void testVerifyInputWithNumericCharacters() {
        // Test with numeric characters
        List<Character> allowed = Arrays.asList('0', '1', '2', '3', '4', '5', '6', '7', '8', '9');
        byte[] input = "0123456789".getBytes();

        assertDoesNotThrow(() -> BotanUtil.verifyInput(input, allowed),
                "verifyInput should not throw for allowed numeric chars");

        // Test with disallowed character
        byte[] invalidInput = "0123a".getBytes();
        assertThrows(IllegalArgumentException.class,
                () -> BotanUtil.verifyInput(invalidInput, allowed),
                "verifyInput should throw for disallowed numeric input");
    }
}
