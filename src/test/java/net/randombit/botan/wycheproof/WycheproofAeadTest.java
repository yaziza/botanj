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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.randombit.botan.spec.AeadParameterSpec;

/** Base class for Wycheproof AEAD test vectors. */
public abstract class WycheproofAeadTest extends WycheproofTestBase {

  /**
   * Run Wycheproof AEAD tests from a JSON file.
   *
   * @param resourcePath path to the Wycheproof JSON test vector file
   * @param transformation JCE transformation string (e.g., "AES/GCM/NoPadding")
   */
  protected void runWycheproofAeadTests(String resourcePath, String transformation)
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
      int tagSize = group.get("tagSize").getAsInt();

      JsonArray tests = group.getAsJsonArray("tests");
      for (JsonElement testElement : tests) {
        JsonObject test = testElement.getAsJsonObject();
        int tcId = test.get("tcId").getAsInt();
        String result = test.get("result").getAsString();

        byte[] key = net.randombit.botan.codec.HexUtils.decode(test.get("key").getAsString());
        byte[] iv = net.randombit.botan.codec.HexUtils.decode(test.get("iv").getAsString());
        byte[] aad = net.randombit.botan.codec.HexUtils.decode(test.get("aad").getAsString());
        byte[] msg = net.randombit.botan.codec.HexUtils.decode(test.get("msg").getAsString());
        byte[] ct = net.randombit.botan.codec.HexUtils.decode(test.get("ct").getAsString());
        byte[] tag = net.randombit.botan.codec.HexUtils.decode(test.get("tag").getAsString());

        try {
          boolean testResult = runAeadTest(transformation, key, iv, aad, msg, ct, tag, tagSize);

          if (result.equals("valid") || result.equals("acceptable")) {
            if (testResult) {
              passed++;
            } else {
              failed++;
              LOG.error("Test {} FAILED: Expected valid/acceptable but decryption failed", tcId);
              printTestDetails(test);
            }
          } else if (result.equals("invalid")) {
            if (!testResult) {
              passed++;
            } else {
              failed++;
              LOG.error("Test {} FAILED: Expected invalid but decryption succeeded", tcId);
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
   * Run a single AEAD test.
   *
   * @return true if decryption succeeded and matched expected plaintext, false otherwise
   */
  private boolean runAeadTest(
      String transformation,
      byte[] key,
      byte[] iv,
      byte[] aad,
      byte[] msg,
      byte[] ct,
      byte[] tag,
      int tagSize) {
    try {
      // Combine ciphertext and tag
      // For AES-SIV, the tag comes BEFORE the ciphertext (tag + ct)
      // For other AEAD modes (GCM, CCM, etc.), the tag comes AFTER (ct + tag)
      byte[] ctWithTag = new byte[ct.length + tag.length];
      if (transformation.toUpperCase().contains("SIV")) {
        // AES-SIV format: tag + ciphertext
        System.arraycopy(tag, 0, ctWithTag, 0, tag.length);
        System.arraycopy(ct, 0, ctWithTag, tag.length, ct.length);
      } else {
        // Other AEAD formats: ciphertext + tag
        System.arraycopy(ct, 0, ctWithTag, 0, ct.length);
        System.arraycopy(tag, 0, ctWithTag, ct.length, tag.length);
      }

      Cipher cipher = Cipher.getInstance(transformation, "Botan");

      // Determine algorithm from transformation
      String algorithm = transformation.split("/")[0];
      SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);

      // Create appropriate parameter spec based on cipher type
      java.security.spec.AlgorithmParameterSpec params =
          createParameterSpec(transformation, iv, tagSize);

      cipher.init(Cipher.DECRYPT_MODE, keySpec, params);

      if (aad.length > 0) {
        cipher.updateAAD(aad);
      }

      byte[] decrypted = cipher.doFinal(ctWithTag);

      // Check if decrypted matches expected message
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
      // System.err.println("Exception in runAeadTest: " + e.getMessage());
      return false;
    }
  }

  /** Create the appropriate parameter spec for the cipher type. */
  private java.security.spec.AlgorithmParameterSpec createParameterSpec(
      String transformation, byte[] iv, int tagSize) {
    String mode = transformation.toUpperCase();

    if (mode.contains("GCM")) {
      return new GCMParameterSpec(tagSize, iv);
    } else if (mode.contains("CCM")
        || mode.contains("EAX")
        || mode.contains("OCB")
        || mode.contains("SIV")) {
      // CCM, EAX, OCB, SIV need tag size - use AeadParameterSpec
      return new AeadParameterSpec(tagSize, iv);
    } else if (mode.contains("CHACHA20")) {
      // ChaCha20-Poly1305 and XChaCha20-Poly1305 use IvParameterSpec
      // ChaCha20: 96-bit nonce, XChaCha20: 192-bit nonce and fixed 128-bit tag length
      return new IvParameterSpec(iv);
    } else {
      // Default to AeadParameterSpec for unknown modes
      return new AeadParameterSpec(tagSize, iv);
    }
  }
}
