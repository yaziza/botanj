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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Botan Hex encoding tests")
public class HexUtilsTest {

  private static final Logger LOG = LogManager.getLogger(HexUtilsTest.class.getSimpleName());

  @Test
  @DisplayName("Test encoding bytes against Bouncy Castle")
  public void testEncode() {
    LOG.info("=== Test: Encoding bytes against Bouncy Castle ===");
    final String input = "some input";
    LOG.info("Input string: '{}'", input);

    final byte[] expected = Hex.encode(input.getBytes());
    final byte[] actual = HexUtils.encode(input.getBytes(), true);

    LOG.info("Expected (Bouncy Castle): {} bytes", expected.length);
    LOG.info("Actual (Botan): {} bytes", actual.length);
    assertArrayEquals(expected, actual, "Hex mismatch with Bouncy Castle ");
    LOG.info("SUCCESS: Hex encoding matches Bouncy Castle");
  }

  @Test
  @DisplayName("Test malformed input")
  public void testMalformedInput() {
    LOG.info("=== Test: Malformed input handling ===");
    final String input = "some malformed input";
    LOG.info("Testing malformed input: '{}'", input);

    LOG.info("Testing string decode with malformed input...");
    Exception exception =
        assertThrows(IllegalArgumentException.class, () -> HexUtils.decode(input));
    assertEquals("Cannot decode malformed input!", exception.getMessage());
    LOG.info("String decode properly rejected malformed input");

    LOG.info("Testing byte array decode with malformed input...");
    exception =
        assertThrows(IllegalArgumentException.class, () -> HexUtils.decode(input.getBytes()));
    assertEquals("Cannot decode malformed input!", exception.getMessage());
    LOG.info("SUCCESS: Byte array decode properly rejected malformed input");
  }

  @Test
  @DisplayName("Test decoding bytes against Bouncy Castle")
  public void testDecode() {
    LOG.info("=== Test: Decoding bytes against Bouncy Castle ===");
    final String expected = "some input";
    LOG.info("Expected output string: '{}'", expected);
    final byte[] input = Hex.encode(expected.getBytes());
    LOG.info("Input (hex encoded): {} bytes", input.length);
    final byte[] actual = HexUtils.decode(input);

    LOG.info("Decoded output: {} bytes", actual.length);
    assertArrayEquals(expected.getBytes(), actual, "Hex mismatch with Bouncy Castle");
    LOG.info("SUCCESS: Hex decoding matches Bouncy Castle");
  }

  @Test
  @DisplayName("Test encoding string against Bouncy Castle")
  public void testDecodeString() {
    LOG.info("=== Test: Decoding string against Bouncy Castle ===");
    final String upperCase = "01 23 45 67 89 AB CD EF";
    final String lowerCase = "01 23 45 67 89 ab cd ef";
    LOG.info("Testing uppercase hex: '{}'", upperCase);
    LOG.info("Testing lowercase hex: '{}'", lowerCase);

    assertArrayEquals(
        Hex.decode(upperCase), HexUtils.decode(upperCase), "Hex mismatch with Bouncy Castle");
    LOG.info("Uppercase decode matches Bouncy Castle");
    assertArrayEquals(
        Hex.decode(lowerCase), HexUtils.decode(lowerCase), "Hex mismatch with Bouncy Castle");
    LOG.info("SUCCESS: Lowercase decode matches Bouncy Castle");
  }

  @Test
  @DisplayName("Test encoding then decoding string")
  public void testEncodeThenDecode() {
    LOG.info("=== Test: Encoding then decoding string ===");
    final String input = "some input";
    LOG.info("Original input: '{}'", input);
    final byte[] encoded = HexUtils.encode(input.getBytes(), true);
    LOG.info("Encoded to: {} bytes", encoded.length);
    final byte[] decoded = HexUtils.decode(encoded);
    LOG.info("Decoded to: {} bytes", decoded.length);

    assertArrayEquals(input.getBytes(), decoded, "Hex mismatch with input");
    LOG.info("SUCCESS: Round-trip encoding/decoding successful");
  }

  @Test
  @DisplayName("Test encoding malformed input")
  public void testDecodeMalformedInput() {
    LOG.info("=== Test: Decoding malformed input ===");
    final String input = "some malformed input";
    LOG.info("Testing malformed input: '{}'", input);

    final Exception exception =
        assertThrows(IllegalArgumentException.class, () -> HexUtils.decode(input));

    assertEquals("Cannot decode malformed input!", exception.getMessage());
    LOG.info("SUCCESS: Properly rejected malformed input with correct error message");
  }
}
