/*
 * (C) 2025 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.wycheproof;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Base class for Wycheproof Cipher test vectors.
 *
 * <p>This class provides infrastructure for testing symmetric ciphers using Wycheproof test
 * vectors. These tests focus on IndCPA (Indistinguishability under Chosen Plaintext Attack)
 * properties of encryption schemes.
 */
public abstract class WycheproofCipherTest extends WycheproofTestBase {

  /**
   * Run Wycheproof cipher tests from a JSON file.
   *
   * @param resourcePath path to the Wycheproof JSON test vector file
   * @param transformation JCE transformation string (e.g., "AES/CBC/PKCS5Padding")
   */
  protected void runWycheproofCipherTests(String resourcePath, String transformation)
      throws Exception {
    JsonObject root = loadTestFile(resourcePath);

    String algorithm = root.get("algorithm").getAsString();
    int numberOfTests = root.get("numberOfTests").getAsInt();

    LOG.info("Running {} Wycheproof test vectors for {}", numberOfTests, algorithm);

    JsonArray testGroups = root.getAsJsonArray("testGroups");
    int passed = 0;
    int failed = 0;
    int skipped = 0;

    for (JsonElement groupElement : testGroups) {
      JsonObject group = groupElement.getAsJsonObject();
      int keySize = group.get("keySize").getAsInt();
      int ivSize = group.get("ivSize").getAsInt();

      JsonArray tests = group.getAsJsonArray("tests");
      for (JsonElement testElement : tests) {
        JsonObject test = testElement.getAsJsonObject();
        int tcId = test.get("tcId").getAsInt();
        String result = test.get("result").getAsString();

        byte[] key = net.randombit.botan.codec.HexUtils.decode(test.get("key").getAsString());
        byte[] iv = net.randombit.botan.codec.HexUtils.decode(test.get("iv").getAsString());
        byte[] msg = net.randombit.botan.codec.HexUtils.decode(test.get("msg").getAsString());
        byte[] ct = net.randombit.botan.codec.HexUtils.decode(test.get("ct").getAsString());

        try {
          boolean testResult = runCipherTest(transformation, key, iv, msg, ct);

          if (result.equals("valid") || result.equals("acceptable")) {
            if (testResult) {
              passed++;
            } else {
              failed++;
              LOG.error(
                  "Test {} FAILED: Expected valid/acceptable but encryption/decryption failed",
                  tcId);
              printTestDetails(test);
            }
          } else if (result.equals("invalid")) {
            if (!testResult) {
              passed++;
            } else {
              failed++;
              LOG.error(
                  "Test {} FAILED: Expected invalid but encryption/decryption succeeded", tcId);
              printTestDetails(test);
            }
          }
        } catch (Exception e) {
          if (result.equals("invalid")) {
            passed++;
          } else {
            failed++;
            LOG.error("Test {} FAILED with exception: {}", tcId, e.getMessage());
            printTestDetails(test);
          }
        }
      }
    }

    logSummaryAndCheckFailures(passed, failed, skipped, numberOfTests, algorithm);
  }

  /**
   * Run a single cipher test.
   *
   * @return true if encryption/decryption succeeded and matched expected values, false otherwise
   */
  private boolean runCipherTest(
      String transformation, byte[] key, byte[] iv, byte[] msg, byte[] ct) {
    try {
      Cipher cipher = Cipher.getInstance(transformation, "Botan");

      // Determine algorithm from transformation
      String algorithm = transformation.split("/")[0];
      SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
      IvParameterSpec ivSpec = new IvParameterSpec(iv);

      // Test encryption
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
      byte[] encrypted = cipher.doFinal(msg);

      // Check if encrypted matches expected ciphertext
      if (!java.util.Arrays.equals(encrypted, ct)) {
        return false;
      }

      // Test decryption
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
      byte[] decrypted = cipher.doFinal(ct);

      // Check if decrypted matches original message
      if (msg.length != decrypted.length) {
        return false;
      }

      for (int i = 0; i < msg.length; i++) {
        if (msg[i] != decrypted[i]) {
          return false;
        }
      }

      return true;
    } catch (Exception e) {
      // Uncomment for debugging:
      // System.err.println("Exception in runCipherTest: " + e.getMessage());
      return false;
    }
  }
}
