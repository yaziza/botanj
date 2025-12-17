/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.block;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jnr.ffi.Pointer;
import net.randombit.botan.BotanProvider;
import net.randombit.botan.codec.HexUtils;
import net.randombit.botan.jnr.BotanInstance;
import net.randombit.botan.jnr.BotanLibrary;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringFormattedMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.mockito.MockedStatic;

@DisplayName("Botan block ciphers tests")
public class BotanBlockCipherTest {

  private static final Logger LOG =
      LogManager.getLogger(BotanBlockCipherTest.class.getSimpleName());

  @BeforeAll
  public static void setUp() {
    Security.addProvider(new BotanProvider());
    Security.addProvider(new BouncyCastleProvider());
  }

  @ParameterizedTest
  @CsvFileSource(
      resources = {
        "/seckey/block/cbc_padding.csv",
        "/seckey/block/cbc_no_padding.csv",
        "/seckey/block/cfb_no_padding.csv"
      },
      numLinesToSkip = 1)
  @DisplayName("Test cipher block size")
  public void testCipherBlockSize(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

    cipher.init(Cipher.ENCRYPT_MODE, key);

    assertEquals(
        blockSize, cipher.getBlockSize(), "Cipher block size mismatch for algorithm: " + algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(
      resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
      numLinesToSkip = 1)
  @DisplayName("Test cipher parameters IV set")
  public void testCipherParametersWithIv(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
    final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    AlgorithmParameters parameters = cipher.getParameters();

    String baseCipher = algorithm.substring(0, algorithm.indexOf('/'));
    assertEquals(baseCipher, parameters.getAlgorithm(), "Cipher name mismatch: " + baseCipher);
  }

  @Test
  @DisplayName("Test unsupported padding algorithm")
  public void testUnsupportedPaddingAlgorithm() {
    final String padding = "some padding";

    final Exception exception =
        assertThrows(
            NoSuchPaddingException.class,
            () -> Cipher.getInstance("AES/CBC/" + padding, BotanProvider.NAME));

    assertEquals("Padding algorithm not supported: " + padding, exception.getMessage());
  }

  @ParameterizedTest
  @CsvFileSource(
      resources = {"/seckey/block/cbc_padding.csv"},
      numLinesToSkip = 1)
  @DisplayName("Test calling cipher update before initialization")
  public void testCipherUpdateWithoutInitialization(String algorithm)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

    final Exception exception =
        assertThrows(IllegalStateException.class, () -> cipher.update(new byte[128]));

    assertEquals("Cipher not initialized", exception.getMessage());
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/seckey/block/cfb_no_padding.csv", numLinesToSkip = 1)
  @DisplayName("Test calling cipher doFinal before initialization")
  public void testCipherDoFinalWithoutInitialization(String algorithm)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

    final Exception exception = assertThrows(IllegalStateException.class, () -> cipher.doFinal());

    assertEquals("Cipher not initialized", exception.getMessage());
  }

  @ParameterizedTest
  @CsvFileSource(
      resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
      numLinesToSkip = 1)
  @DisplayName("Test calling cipher doFinal without input (No Padding)")
  public void testCipherDoFinalWithoutInputNoPadding(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
    final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] output = cipher.doFinal();

    assertEquals(0, output.length, "doFinal without input should produce no output");
  }

  @ParameterizedTest
  @CsvFileSource(
      resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
      numLinesToSkip = 1)
  @DisplayName("Test calling cipher doFinal with output offset")
  public void testCipherDoFinalWithOutputOffset(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
    final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

    final byte[] output = new byte[64];
    final int outputOffset = 22;

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    int outputLength = cipher.doFinal(new byte[blockSize], 0, blockSize, output, outputOffset);

    assertNotEquals(outputLength, output.length, "Cipher doFinal should only encrypt from offset");
    assertEquals(outputLength, blockSize, "Cipher doFinal output length mismatch");

    // 0 to outputOffset must stay the same
    assertArrayEquals(new byte[outputOffset], Arrays.copyOfRange(output, 0, outputOffset));

    // outputOffset + block size to array end must stay the same
    assertArrayEquals(
        new byte[output.length - outputOffset - blockSize],
        Arrays.copyOfRange(output, outputOffset + blockSize, output.length));

    // data from outputOffset must be encrypted
    assertArrayEquals(
        cipher.doFinal(new byte[blockSize]),
        Arrays.copyOfRange(output, outputOffset, outputOffset + blockSize));
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/seckey/block/cbc_padding.csv", numLinesToSkip = 1)
  @DisplayName("Test calling cipher doFinal without input (With Padding)")
  public void testCipherDoFinalWithoutInputWithPadding(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
    final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] output = cipher.doFinal();

    assertEquals(blockSize, output.length, "doFinal without input should produce no output");
  }

  @ParameterizedTest
  @CsvFileSource(
      resources = {
        "/seckey/block/cbc_padding.csv",
        "/seckey/block/cfb_no_padding.csv",
        "/seckey/block/cfb_no_padding.csv"
      },
      numLinesToSkip = 1)
  @DisplayName("Test encrypting then decrypting cipher")
  public void testEncryptThenDecrypt(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);
    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
    final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

    final byte[] expected = "some plain text to be encrypted.".getBytes();

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] cipherText = cipher.doFinal(expected);

    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    final byte[] plainText = cipher.doFinal(cipherText);

    assertArrayEquals(
        expected, plainText, "Encrypt than decrypt mismatch for algorithm: " + algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(
      resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
      numLinesToSkip = 1)
  @DisplayName("Test cipher encrypt(no padding) against bouncy castle")
  public void testEncryptNoPaddingAgainstBouncyCastle(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final Cipher bc = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    final Cipher botan = Cipher.getInstance(algorithm, BotanProvider.NAME);

    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
    final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

    bc.init(Cipher.ENCRYPT_MODE, key, iv);
    botan.init(Cipher.ENCRYPT_MODE, key, iv);

    final byte[] input = new byte[blockSize * Byte.SIZE * 10];

    byte[] expected = bc.doFinal(input);
    byte[] actual = botan.doFinal(input);

    assertArrayEquals(
        expected,
        actual,
        "Encryption mismatch with Bouncy Castle provider for algorithm " + algorithm);
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/seckey/block/cbc_no_padding.csv", numLinesToSkip = 1)
  @DisplayName("Test cipher data not block size aligned")
  public void testEncryptDataNotBlockSizeAligned(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
    final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    cipher.update(new byte[2]);

    Exception exception = assertThrows(IllegalBlockSizeException.class, () -> cipher.doFinal());
    assertEquals("Data not block size aligned", exception.getMessage());

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);

    exception = assertThrows(IllegalBlockSizeException.class, () -> cipher.doFinal(new byte[1]));
    assertEquals("Data not block size aligned", exception.getMessage());
  }

  @ParameterizedTest
  @CsvFileSource(resources = "/seckey/block/cbc_padding.csv", numLinesToSkip = 1)
  @DisplayName("Test cipher correct padding length")
  public void testCorrectPaddingLength(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
    final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    byte[] output = cipher.doFinal(new byte[0]);

    assertEquals(blockSize, output.length, "Cipher padding incorrect size");

    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    output = cipher.doFinal(new byte[blockSize]);

    assertEquals(blockSize * 2, output.length, "Cipher padding incorrect size");
  }

  @ParameterizedTest
  @CsvFileSource(
      resources = {"/seckey/block/cbc_test_vectors.csv", "/seckey/block/cfb_test_vectors.csv"},
      numLinesToSkip = 1)
  @DisplayName("Test block cipher encryption with test vectors")
  public void testCipherWithTestVectors(
      String algorithm, String key, String iv, String in, String out)
      throws GeneralSecurityException {
    final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.NAME);

    final SecretKeySpec keyBytes = new SecretKeySpec(HexUtils.decode(key), algorithm);
    final IvParameterSpec ivBytes = new IvParameterSpec(HexUtils.decode(iv));

    cipher.init(Cipher.ENCRYPT_MODE, keyBytes, ivBytes);

    byte[] cipherText = cipher.doFinal(HexUtils.decode(in));

    assertArrayEquals(HexUtils.decode(out), cipherText, "Encryption mismatch with test vector");
  }

  @ParameterizedTest
  @CsvFileSource(
      resources = {"/seckey/block/cbc_no_padding.csv", "/seckey/block/cfb_no_padding.csv"},
      numLinesToSkip = 1)
  @DisplayName("Test Botan performance against Bouncy Castle")
  public void testBotanPerformanceAgainstBouncyCastle(String algorithm, int blockSize, int keySize)
      throws GeneralSecurityException {
    final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
    final AlgorithmParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

    final Cipher bc = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
    final Cipher botan = Cipher.getInstance(algorithm, BotanProvider.NAME);

    bc.init(Cipher.ENCRYPT_MODE, key, iv);
    botan.init(Cipher.ENCRYPT_MODE, key, iv);

    byte[] input = new byte[10_240];

    final long startBc = System.nanoTime();
    final byte[] expected = bc.doFinal(input);
    final long endBc = System.nanoTime();

    final long startBotan = System.nanoTime();
    final byte[] actual = botan.doFinal(input);
    final long endBotan = System.nanoTime();

    double difference = (endBc - startBc) - (endBotan - startBotan);
    difference /= (endBc - startBc);
    difference *= 100;

    LOG.info(
        new StringFormattedMessage(
            "Performance against Bouncy Castle for algorithm with key size: %s(%d): %.2f %%",
            algorithm, keySize, difference));

    assertArrayEquals(
        expected, actual, "Cipher mismatch with Bouncy Castle provider for algorithm " + algorithm);
  }

  @Test
  @DisplayName("Verify botan_cipher_destroy is called correct number of times on multiple re-inits")
  public void testDestroyCalledMultipleTimes() throws Exception {
    LOG.info("=== Mock Test: Verify destroy count on multiple cipher re-inits ===");

    BotanLibrary realLibrary = BotanInstance.singleton();
    BotanLibrary spyLibrary = spy(realLibrary);

    try (MockedStatic<BotanInstance> mockedStatic = mockStatic(BotanInstance.class)) {
      mockedStatic.when(BotanInstance::singleton).thenReturn(spyLibrary);

      LOG.info("Creating Cipher and re-initializing 5 times...");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7", BotanProvider.NAME);

      SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
      IvParameterSpec iv = new IvParameterSpec(new byte[16]);

      // First init - no destroy expected yet
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);
      cipher.doFinal("test".getBytes());

      // Clear initial calls
      clearInvocations(spyLibrary);

      // Re-init 5 times - should call destroy 5 times
      for (int i = 1; i <= 5; i++) {
        byte[] keyBytes = new byte[16];
        keyBytes[0] = (byte) i;
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");

        byte[] ivBytes = new byte[16];
        ivBytes[0] = (byte) i;
        IvParameterSpec newIv = new IvParameterSpec(ivBytes);

        cipher.init(Cipher.ENCRYPT_MODE, newKey, newIv);
        cipher.doFinal("test".getBytes());
        LOG.info("   Re-init #{} completed", i);
      }

      // Verify destroy was called exactly 5 times (once per re-init)
      LOG.info("Verifying destroy count...");
      verify(spyLibrary, times(5)).botan_cipher_destroy(any(Pointer.class));

      LOG.info("VERIFICATION SUCCESS!");
      LOG.info("   - botan_cipher_destroy() called exactly 5 times");
      LOG.info("   - One destroy per re-initialization");
      LOG.info("   - Cleanup mechanism is precise and correct");
    }
  }

  @Test
  @DisplayName("Verify botan_cipher_destroy is NOT called during normal update/doFinal operations")
  public void testDestroyNotCalledDuringNormalOps() throws Exception {
    LOG.info("=== Mock Test: Verify destroy NOT called during normal cipher ops ===");

    BotanLibrary realLibrary = BotanInstance.singleton();
    BotanLibrary spyLibrary = spy(realLibrary);

    try (MockedStatic<BotanInstance> mockedStatic = mockStatic(BotanInstance.class)) {
      mockedStatic.when(BotanInstance::singleton).thenReturn(spyLibrary);

      LOG.info("Creating and using Cipher without re-initialization...");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7", BotanProvider.NAME);

      SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
      IvParameterSpec iv = new IvParameterSpec(new byte[16]);

      cipher.init(Cipher.ENCRYPT_MODE, key, iv);

      // Clear invocations after init
      clearInvocations(spyLibrary);

      // Perform normal operations
      LOG.info("   - update() operation");
      cipher.update("data 1".getBytes());

      LOG.info("   - doFinal() operation");
      cipher.doFinal();

      LOG.info("   - update() again");
      cipher.update("data 2".getBytes());

      LOG.info("   - doFinal() again");
      cipher.doFinal();

      // Verify destroy was NOT called during these operations
      LOG.info("Verifying destroy was NOT called...");
      verify(spyLibrary, never()).botan_cipher_destroy(any(Pointer.class));

      LOG.info("VERIFICATION SUCCESS!");
      LOG.info("   - botan_cipher_destroy() NOT called during normal operations");
      LOG.info("   - Destroy only happens on re-init or GC");
      LOG.info("   - Behavior is correct and safe");
    }
  }

  // ===== Edge Case Tests =====

  @Test
  @DisplayName("Test cipher creation")
  void testCipherCreation() throws Exception {
    // Test that we can create a cipher instance successfully
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7", "Botan");
    assertEquals("Botan", cipher.getProvider().getName(), "Cipher provider should be Botan");
  }

  @Test
  @DisplayName("Test doFinal with empty input")
  void testEmptyDoFinal() throws Exception {
    // Test doFinal with empty input
    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "Botan");

    byte[] key = new byte[16]; // 128-bit key
    byte[] iv = new byte[16];
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

    // Empty input should work for stream ciphers
    byte[] result = cipher.doFinal(new byte[0]);
    assertEquals(0, result.length, "Result should be empty for empty input");
  }

  @Test
  @DisplayName("Test multiple cipher re-initializations")
  void testMultipleInitializations() throws Exception {
    // Test re-initialization with different keys
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7", "Botan");

    // First initialization
    byte[] key1 = new byte[16];
    key1[0] = 1;
    byte[] iv1 = new byte[16];
    SecretKeySpec keySpec1 = new SecretKeySpec(key1, "AES");
    IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);

    cipher.init(Cipher.ENCRYPT_MODE, keySpec1, ivSpec1);
    byte[] plaintext = "Test message".getBytes();
    byte[] ciphertext1 = cipher.doFinal(plaintext);

    // Re-initialize with different key
    byte[] key2 = new byte[16];
    key2[0] = 2;
    byte[] iv2 = new byte[16];
    SecretKeySpec keySpec2 = new SecretKeySpec(key2, "AES");
    IvParameterSpec ivSpec2 = new IvParameterSpec(iv2);

    cipher.init(Cipher.ENCRYPT_MODE, keySpec2, ivSpec2);
    byte[] ciphertext2 = cipher.doFinal(plaintext);

    // Ciphertexts should be different
    assertNotEquals(
        Arrays.hashCode(ciphertext1),
        Arrays.hashCode(ciphertext2),
        "Different keys should produce different ciphertexts");
  }

  @Test
  @DisplayName("Test getIV returns correct IV")
  void testGetIV() throws Exception {
    // Test that getIV returns the correct IV
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7", "Botan");

    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    for (int i = 0; i < 16; i++) {
      iv[i] = (byte) i;
    }

    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

    byte[] retrievedIv = cipher.getIV();
    assertArrayEquals(iv, retrievedIv, "Retrieved IV should match the one provided");
  }

  @Test
  @DisplayName("Test getBlockSize for different ciphers")
  void testGetBlockSize() throws Exception {
    // Test getBlockSize for block ciphers
    Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS7", "Botan");
    assertEquals(16, aesCipher.getBlockSize(), "AES block size should be 16 bytes");

    // Stream ciphers should return 0 or 1 for block size
    Cipher streamCipher = Cipher.getInstance("ChaCha20/None/NoPadding", "Botan");
    assertEquals(1, streamCipher.getBlockSize(), "ChaCha20 stream cipher block size should be 1");
  }

  @Test
  @DisplayName("Test incremental update processing")
  void testIncrementalUpdate() throws Exception {
    // Test incremental processing with update
    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "Botan");

    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

    // Process data incrementally
    byte[] part1 = "Hello ".getBytes();
    byte[] part2 = "World".getBytes();

    byte[] encrypted1 = cipher.update(part1);
    byte[] encrypted2 = cipher.update(part2);
    byte[] finalPart = cipher.doFinal();

    // Combine all parts
    int totalLength =
        (encrypted1 != null ? encrypted1.length : 0)
            + (encrypted2 != null ? encrypted2.length : 0)
            + (finalPart != null ? finalPart.length : 0);
    byte[] combined = new byte[totalLength];

    int offset = 0;
    if (encrypted1 != null) {
      System.arraycopy(encrypted1, 0, combined, offset, encrypted1.length);
      offset += encrypted1.length;
    }
    if (encrypted2 != null) {
      System.arraycopy(encrypted2, 0, combined, offset, encrypted2.length);
      offset += encrypted2.length;
    }
    if (finalPart != null) {
      System.arraycopy(finalPart, 0, combined, offset, finalPart.length);
    }

    // Decrypt to verify
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    byte[] decrypted = cipher.doFinal(combined);

    String original = "Hello World";
    assertEquals(original, new String(decrypted), "Decrypted text should match original");
  }

  @Test
  @DisplayName("Test update with offset and length")
  void testUpdateWithOffset() throws Exception {
    // Test update with offset and length parameters
    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "Botan");

    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

    // Create input with extra data at the beginning and end
    byte[] input = "XXXTestDataYYY".getBytes();
    int offset = 3;
    int length = 8; // "TestData"

    byte[] output = new byte[cipher.getOutputSize(length)];
    int outputLen = cipher.update(input, offset, length, output, 0);

    byte[] finalPart = cipher.doFinal();

    // Verify by decrypting
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    byte[] decrypted = cipher.doFinal(output, 0, outputLen);

    assertEquals(
        "TestData", new String(decrypted), "Decrypted text should match the extracted portion");
  }

  @Test
  @DisplayName("Test getOutputSize calculation")
  void testGetOutputSize() throws Exception {
    // Test getOutputSize for block ciphers
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7", "Botan");

    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

    // For block ciphers with padding, output size should account for padding
    int inputLen = 10;
    int outputSize = cipher.getOutputSize(inputLen);

    // With PKCS7 padding, output should be rounded up to next block (16 bytes)
    assertEquals(
        16,
        outputSize,
        "Output size should be 16 bytes (one block) for 10-byte input with padding");
  }

  @Test
  @DisplayName("Test different AES key sizes")
  void testDifferentKeySizes() throws Exception {
    // Test with different AES key sizes: 128, 192, 256 bits
    int[] keySizes = {16, 24, 32};

    for (int keySize : keySizes) {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7", "Botan");

      byte[] key = new byte[keySize];
      byte[] iv = new byte[16];
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      IvParameterSpec ivSpec = new IvParameterSpec(iv);

      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

      byte[] plaintext = "Test message".getBytes();
      byte[] ciphertext = cipher.doFinal(plaintext);

      // Decrypt to verify
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
      byte[] decrypted = cipher.doFinal(ciphertext);

      assertArrayEquals(
          plaintext,
          decrypted,
          "Decrypted text should match original for key size " + (keySize * 8));
    }
  }
}
