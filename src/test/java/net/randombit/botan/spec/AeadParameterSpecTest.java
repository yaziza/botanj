/*
 * (C) 2025 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.spec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;

@DisplayName("AeadParameterSpec tests")
public class AeadParameterSpecTest {

    private static final Logger LOG = LogManager.getLogger(AeadParameterSpecTest.class.getSimpleName());

    @Test
    @DisplayName("Test basic constructor")
    public void testBasicConstructor() {
        LOG.info("=== Test: Basic constructor ===");
        byte[] nonce = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        int tLen = 128;

        AeadParameterSpec spec = new AeadParameterSpec(tLen, nonce);

        LOG.info("Nonce length: {} bytes", spec.getIV().length);
        LOG.info("Tag length: {} bits", spec.getTLen());

        assertArrayEquals(nonce, spec.getIV(), "IV should match nonce");
        assertEquals(tLen, spec.getTLen(), "Tag length should match");
        LOG.info("SUCCESS: Basic constructor works correctly");
    }

    @Test
    @DisplayName("Test null nonce throws exception")
    public void testNullNonceThrowsException() {
        LOG.info("=== Test: Null nonce throws exception ===");
        byte[] nonce = null;
        int tLen = 128;

        assertThrows(IllegalArgumentException.class, () -> {
            new AeadParameterSpec(tLen, nonce);
        }, "Should throw IllegalArgumentException for null nonce");
        LOG.info("SUCCESS: Null nonce properly rejected");
    }

    @Test
    @DisplayName("Test negative tag length throws exception")
    public void testNegativeMacSizeThrowsException() {
        LOG.info("=== Test: Negative tag length throws exception ===");
        byte[] nonce = new byte[12];
        int tLen = -1;

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new AeadParameterSpec(tLen, nonce);
        }, "Should throw IllegalArgumentException for negative tag length");

        assertEquals("Tag length cannot be negative", exception.getMessage());
        LOG.info("SUCCESS: Negative tag length properly rejected");
    }

    @Test
    @DisplayName("Test tag length not multiple of 8 throws exception")
    public void testMacSizeNotMultipleOf8ThrowsException() {
        LOG.info("=== Test: Tag length not multiple of 8 throws exception ===");
        byte[] nonce = new byte[12];
        int tLen = 127; // Not a multiple of 8

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            new AeadParameterSpec(tLen, nonce);
        }, "Should throw IllegalArgumentException for tag length not multiple of 8");

        assertEquals("Tag length must be a multiple of 8 bits", exception.getMessage());
        LOG.info("SUCCESS: Invalid tag length properly rejected");
    }

    @Test
    @DisplayName("Test defensive copy of nonce")
    public void testDefensiveCopyOfNonce() {
        LOG.info("=== Test: Defensive copy of nonce ===");
        byte[] originalNonce = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        byte[] nonceCopy = Arrays.copyOf(originalNonce, originalNonce.length);
        int tLen = 128;

        AeadParameterSpec spec = new AeadParameterSpec(tLen, nonceCopy);

        // Modify the original array
        nonceCopy[0] = 99;

        LOG.info("Original nonce[0]: {}", originalNonce[0]);
        LOG.info("Modified copy[0]: {}", nonceCopy[0]);
        LOG.info("Spec nonce[0]: {}", spec.getIV()[0]);

        // The spec's nonce should not be affected
        assertEquals(originalNonce[0], spec.getIV()[0], "Spec nonce should not be affected by external changes");
        assertNotEquals(nonceCopy[0], spec.getIV()[0], "Spec nonce should differ from modified copy");
        LOG.info("SUCCESS: Nonce is defensively copied");
    }

    @Test
    @DisplayName("Test returned arrays are copies")
    public void testReturnedArraysAreCopies() {
        LOG.info("=== Test: Returned arrays are copies ===");
        byte[] nonce = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        int tLen = 128;

        AeadParameterSpec spec = new AeadParameterSpec(tLen, nonce);

        // Get arrays
        byte[] returnedNonce1 = spec.getIV();
        byte[] returnedNonce2 = spec.getIV();

        // Returned arrays should not be the same instance
        assertNotSame(returnedNonce1, returnedNonce2, "Each getIV() call should return a new array");

        // But they should have the same content
        assertArrayEquals(returnedNonce1, returnedNonce2, "Nonce content should be the same");

        // Modifying returned arrays should not affect the spec
        returnedNonce1[0] = 99;

        assertEquals(nonce[0], spec.getIV()[0], "Spec nonce should not be affected");
        LOG.info("SUCCESS: Returned arrays are independent copies");
    }

    @Test
    @DisplayName("Test equals and hashCode")
    public void testEqualsAndHashCode() {
        LOG.info("=== Test: equals and hashCode ===");
        byte[] nonce = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        int tLen = 128;

        AeadParameterSpec spec1 = new AeadParameterSpec(tLen, nonce);
        AeadParameterSpec spec2 = new AeadParameterSpec(tLen, nonce);
        AeadParameterSpec spec3 = new AeadParameterSpec(96, nonce);
        AeadParameterSpec spec4 = new AeadParameterSpec(tLen, new byte[12]);

        // Equal objects
        assertEquals(spec1, spec2, "Identical specs should be equal");
        assertEquals(spec1.hashCode(), spec2.hashCode(), "Equal specs should have same hash code");

        // Different tag length
        assertNotEquals(spec1, spec3, "Specs with different tag lengths should not be equal");

        // Different nonce
        assertNotEquals(spec1, spec4, "Specs with different nonces should not be equal");

        // Self equality
        assertEquals(spec1, spec1, "Spec should equal itself");

        // Null comparison
        assertNotEquals(spec1, null, "Spec should not equal null");

        // Different class
        assertNotEquals(spec1, new Object(), "Spec should not equal object of different class");

        LOG.info("SUCCESS: equals and hashCode work correctly");
    }

    @Test
    @DisplayName("Test toString")
    public void testToString() {
        LOG.info("=== Test: toString ===");
        byte[] nonce = new byte[12];
        int tLen = 128;

        AeadParameterSpec spec = new AeadParameterSpec(tLen, nonce);

        String str = spec.toString();

        LOG.info("toString: {}", str);

        assertTrue(str.contains("nonceLength=12"), "Should include nonce length");
        assertTrue(str.contains("tLen=128"), "Should include tag length");

        LOG.info("SUCCESS: toString provides useful information");
    }

    @Test
    @DisplayName("Test various valid tag lengths")
    public void testVariousValidMacSizes() {
        LOG.info("=== Test: Various valid tag lengths ===");
        byte[] nonce = new byte[12];
        int[] validTagLengths = {8, 16, 24, 32, 64, 96, 104, 112, 120, 128, 256};

        for (int tagLength : validTagLengths) {
            LOG.info("Testing tag length: {} bits", tagLength);
            AeadParameterSpec spec = new AeadParameterSpec(tagLength, nonce);
            assertEquals(tagLength, spec.getTLen(), "Tag length should be " + tagLength);
        }
        LOG.info("SUCCESS: All valid tag lengths accepted");
    }

    @Test
    @DisplayName("Test large nonce")
    public void testLargeNonce() {
        LOG.info("=== Test: Large nonce ===");
        byte[] largeNonce = new byte[1024]; // Large nonce
        int tLen = 128;

        // Fill with some data
        Arrays.fill(largeNonce, (byte) 0x42);

        AeadParameterSpec spec = new AeadParameterSpec(tLen, largeNonce);

        LOG.info("Large nonce length: {} bytes", spec.getIV().length);

        assertEquals(1024, spec.getIV().length, "Nonce length should be preserved");
        assertArrayEquals(largeNonce, spec.getIV(), "Large nonce should match");
        LOG.info("SUCCESS: Large nonce handled correctly");
    }

    @Test
    @DisplayName("Test zero tag length")
    public void testZeroMacSize() {
        LOG.info("=== Test: Zero tag length ===");
        byte[] nonce = new byte[12];
        int tLen = 0;

        AeadParameterSpec spec = new AeadParameterSpec(tLen, nonce);

        assertEquals(0, spec.getTLen(), "Tag length should be 0");
        LOG.info("SUCCESS: Zero tag length accepted");
    }

    @Test
    @DisplayName("Test constructor with offset and length")
    public void testConstructorWithOffsetAndLength() {
        LOG.info("=== Test: Constructor with offset and length ===");
        byte[] buffer = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        int offset = 4;
        int len = 12;
        int tLen = 128;

        AeadParameterSpec spec = new AeadParameterSpec(tLen, buffer, offset, len);

        LOG.info("Buffer length: {} bytes", buffer.length);
        LOG.info("Offset: {}, Length: {}", offset, len);
        LOG.info("Extracted IV length: {} bytes", spec.getIV().length);

        assertEquals(len, spec.getIV().length, "IV length should match specified length");
        assertEquals(tLen, spec.getTLen(), "Tag length should match");

        // Verify the correct bytes were extracted
        byte[] expectedIV = new byte[]{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        assertArrayEquals(expectedIV, spec.getIV(), "IV should contain correct bytes from offset");

        LOG.info("SUCCESS: Constructor with offset and length works correctly");
    }

    @Test
    @DisplayName("Test constructor with invalid offset")
    public void testConstructorWithInvalidOffset() {
        LOG.info("=== Test: Constructor with invalid offset ===");
        byte[] buffer = new byte[16];
        int offset = -1;
        int len = 12;
        int tLen = 128;

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            new AeadParameterSpec(tLen, buffer, offset, len);
        }, "Should throw ArrayIndexOutOfBoundsException for negative offset");

        LOG.info("SUCCESS: Negative offset properly rejected");
    }

    @Test
    @DisplayName("Test constructor with invalid length")
    public void testConstructorWithInvalidLength() {
        LOG.info("=== Test: Constructor with invalid length ===");
        byte[] buffer = new byte[16];
        int offset = 4;
        int len = -1;
        int tLen = 128;

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            new AeadParameterSpec(tLen, buffer, offset, len);
        }, "Should throw ArrayIndexOutOfBoundsException for negative length");

        LOG.info("SUCCESS: Negative length properly rejected");
    }

    @Test
    @DisplayName("Test constructor with offset and length exceeding buffer")
    public void testConstructorWithExceedingRange() {
        LOG.info("=== Test: Constructor with offset and length exceeding buffer ===");
        byte[] buffer = new byte[16];
        int offset = 10;
        int len = 12; // offset + len = 22 > 16
        int tLen = 128;

        assertThrows(IllegalArgumentException.class, () -> {
            new AeadParameterSpec(tLen, buffer, offset, len);
        }, "Should throw IllegalArgumentException when offset + length exceeds buffer");

        LOG.info("SUCCESS: Exceeding range properly rejected");
    }

    @Test
    @DisplayName("Test constructor with zero length")
    public void testConstructorWithZeroLength() {
        LOG.info("=== Test: Constructor with zero length ===");
        byte[] buffer = new byte[16];
        int offset = 4;
        int len = 0;
        int tLen = 128;

        AeadParameterSpec spec = new AeadParameterSpec(tLen, buffer, offset, len);

        assertEquals(0, spec.getIV().length, "IV length should be 0");
        assertEquals(tLen, spec.getTLen(), "Tag length should match");

        LOG.info("SUCCESS: Zero length IV accepted");
    }

    @Test
    @DisplayName("Test defensive copy with offset constructor")
    public void testDefensiveCopyWithOffsetConstructor() {
        LOG.info("=== Test: Defensive copy with offset constructor ===");
        byte[] buffer = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        int offset = 4;
        int len = 12;
        int tLen = 128;

        AeadParameterSpec spec = new AeadParameterSpec(tLen, buffer, offset, len);

        // Modify the original buffer
        buffer[4] = 99;
        buffer[5] = 98;

        LOG.info("Modified buffer[4]: {}", buffer[4]);
        LOG.info("Spec IV[0]: {}", spec.getIV()[0]);

        // The spec's IV should not be affected
        assertEquals(4, spec.getIV()[0], "Spec IV should not be affected by external changes");
        assertNotEquals(buffer[4], spec.getIV()[0], "Spec IV should differ from modified buffer");

        LOG.info("SUCCESS: IV is defensively copied with offset constructor");
    }
}
