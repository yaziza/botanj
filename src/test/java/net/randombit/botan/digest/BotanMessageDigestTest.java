/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.digest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import net.randombit.botan.BotanProvider;
import net.randombit.botan.codec.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringFormattedMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

@DisplayName("Botan message digest tests")
public class BotanMessageDigestTest {

  private static final Logger LOG =
      LogManager.getLogger(BotanMessageDigestTest.class.getSimpleName());

  @BeforeAll
  public static void setUp() {
    Security.addProvider(new BotanProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
  @DisplayName("Test digest output size")
  public void testDigestOutputSize(String algorithm, int size) throws GeneralSecurityException {
    LOG.info("=== Test: Digest output size for {} ===", algorithm);
    final MessageDigest digest = MessageDigest.getInstance(algorithm, BotanProvider.NAME);
    final byte[] output = digest.digest("Some input".getBytes());

    LOG.info("Expected size: {} bytes", size);
    LOG.info("Actual output size: {} bytes", output.length);
    assertEquals(
        size, digest.getDigestLength(), "Output size mismatch for algorithm: " + algorithm);
    assertEquals(size, output.length, "Output size mismatch for algorithm: " + algorithm);
    LOG.info("SUCCESS: Output size matches for {}", algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
  @DisplayName("Test digest output against Bouncy Castle")
  public void testAgainstBouncyCastle(String algorithm) throws GeneralSecurityException {
    LOG.info("=== Test: Digest {} against Bouncy Castle ===", algorithm);
    final MessageDigest bc =
        MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

    final byte[] expected = bc.digest("hello world".getBytes());
    final byte[] actual = botan.digest("hello world".getBytes());

    LOG.info("Bouncy Castle output: {} bytes", expected.length);
    LOG.info("Botan output: {} bytes", actual.length);
    assertArrayEquals(
        expected,
        actual,
        "Digest mismatch with Bouncy Castle provider for algorithm: " + algorithm);
    LOG.info("SUCCESS: {} matches Bouncy Castle", algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
  @DisplayName("Test clone digest")
  public void testCloneDigest(String algorithm)
      throws GeneralSecurityException, CloneNotSupportedException {
    LOG.info("=== Test: Clone digest for {} ===", algorithm);
    final MessageDigest bc =
        MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);
    LOG.info("Cloning {} digest instance...", algorithm);
    final MessageDigest clone = (MessageDigest) botan.clone();

    final byte[] expected = bc.digest("Clone supported".getBytes());
    final byte[] actual = clone.digest("Clone supported".getBytes());

    LOG.info("Expected (BC): {} bytes", expected.length);
    LOG.info("Actual (cloned): {} bytes", actual.length);
    assertArrayEquals(
        expected,
        actual,
        "Digest mismatch with Bouncy Castle provider for algorithm: " + algorithm);
    LOG.info("SUCCESS: Clone operation works for {}", algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
  @DisplayName("Test rest digest")
  public void testRestDigest(String algorithm) throws GeneralSecurityException {
    LOG.info("=== Test: Reset digest for {} ===", algorithm);
    final MessageDigest bc =
        MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

    LOG.info("Updating with 'to reset', then resetting...");
    botan.update("to reset".getBytes());
    botan.reset();

    LOG.info("Updating both digests with 'Rest support'...");
    bc.update("Rest support".getBytes());
    botan.update("Rest support".getBytes());

    final byte[] expected = bc.digest();
    final byte[] actual = botan.digest();

    LOG.info("Expected (BC): {} bytes", expected.length);
    LOG.info("Actual (Botan after reset): {} bytes", actual.length);
    assertArrayEquals(
        expected,
        actual,
        "Digest mismatch with Bouncy Castle provider for algorithm: " + algorithm);
    LOG.info("SUCCESS: Reset works correctly for {}", algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
  @DisplayName("Test reset before update")
  public void testResetBeforeUpdate(String algorithm) throws GeneralSecurityException {
    LOG.info("=== Test: Reset before update for {} ===", algorithm);
    final MessageDigest bc =
        MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

    LOG.info("Calling reset on newly initialized digest (before any update)...");
    botan.reset();

    LOG.info("Updating both digests with 'Hello World'...");
    bc.update("Hello World".getBytes());
    botan.update("Hello World".getBytes());

    final byte[] expected = bc.digest();
    final byte[] actual = botan.digest();

    LOG.info("Expected (BC): {} bytes", expected.length);
    LOG.info("Actual (Botan after reset before update): {} bytes", actual.length);
    assertArrayEquals(
        expected,
        actual,
        "Digest mismatch with Bouncy Castle provider for algorithm: " + algorithm);
    LOG.info("SUCCESS: Reset before update works correctly for {}", algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
  @DisplayName("Test multiple reset after digest")
  public void testMultipleResetAfterDigest(String algorithm) throws GeneralSecurityException {
    LOG.info("=== Test: Multiple reset after digest for {} ===", algorithm);
    final MessageDigest bc =
        MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

    LOG.info("Computing digest...");
    botan.update("First message".getBytes());
    botan.digest();

    LOG.info("Calling reset twice (both should be no-op after digest)...");
    botan.reset();
    botan.reset();

    LOG.info("Updating both digests with 'Second message'...");
    bc.update("Second message".getBytes());
    botan.update("Second message".getBytes());

    final byte[] expected = bc.digest();
    final byte[] actual = botan.digest();

    LOG.info("Expected (BC): {} bytes", expected.length);
    LOG.info("Actual (Botan after multiple resets): {} bytes", actual.length);
    assertArrayEquals(
        expected,
        actual,
        "Digest mismatch with Bouncy Castle provider for algorithm: " + algorithm);
    LOG.info("SUCCESS: Multiple reset after digest works correctly for {}", algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
  @DisplayName("Test digest single byte update")
  public void testSingleByteUpdate(String algorithm) throws GeneralSecurityException {
    LOG.info("=== Test: Single byte update for {} ===", algorithm);
    final MessageDigest bc =
        MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

    LOG.info("Updating Botan digest byte-by-byte: 'H', 'e', 'l', 'l', 'o'");
    botan.update((byte) 'H');
    botan.update((byte) 'e');
    botan.update((byte) 'l');
    botan.update((byte) 'l');
    botan.update((byte) 'o');

    LOG.info("Updating BC digest with full string: 'Hello'");
    bc.update("Hello".getBytes());

    final byte[] expected = bc.digest();
    final byte[] actual = botan.digest();

    LOG.info("Expected (BC): {} bytes", expected.length);
    LOG.info("Actual (Botan byte-by-byte): {} bytes", actual.length);
    assertArrayEquals(
        expected,
        actual,
        "Digest mismatch with Bouncy Castle provider for algorithm: " + algorithm);
    LOG.info("SUCCESS: Single byte updates work correctly for {}", algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/digest/test_vectors.csv", numLinesToSkip = 1)
  @DisplayName("Test digests with test vectors")
  public void testDigestWithTestVectors(String algorithm, String in, String out)
      throws NoSuchProviderException, NoSuchAlgorithmException {
    LOG.info("=== Test: {} with test vector ===", algorithm);
    final MessageDigest digest = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

    final byte[] input = HexUtils.decode(in);
    final byte[] expected = HexUtils.decode(out);

    LOG.info("Input: {} bytes", input.length);
    LOG.info("Expected output: {} bytes", expected.length);
    final byte[] actual = digest.digest(input);
    LOG.info("Actual output: {} bytes", actual.length);

    assertArrayEquals(expected, actual, "Digest mismatch with test vector");
    LOG.info("SUCCESS: {} matches test vector", algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/digest/hash.csv", numLinesToSkip = 1)
  @DisplayName("Test Botan performance against Bouncy Castle")
  public void testBotanPerformance(String algorithm) throws GeneralSecurityException {
    final MessageDigest bc =
        MessageDigest.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    final MessageDigest botan = MessageDigest.getInstance(algorithm, BotanProvider.NAME);

    final long startBc = System.nanoTime();
    for (int i = 0; i < 1_000; i++) {
      bc.update("some input".getBytes());
    }
    final byte[] expected = bc.digest();
    final long endBc = System.nanoTime();

    final long startBotan = System.nanoTime();
    for (int i = 0; i < 1_000; i++) {
      botan.update("some input".getBytes());
    }
    final byte[] actual = botan.digest();
    final long endBotan = System.nanoTime();

    double difference = (endBc - startBc) - (endBotan - startBotan);
    difference /= (endBc - startBc);
    difference *= 100;

    LOG.info(
        new StringFormattedMessage(
            "Performance against Bouncy Castle for algorithm %s: %.2f %%", algorithm, difference));

    assertArrayEquals(
        expected,
        actual,
        "Digest mismatch with Bouncy Castle provider for algorithm: " + algorithm);
  }
}
