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
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Base class for Wycheproof MAC test vectors. */
public abstract class WycheproofMacTest extends WycheproofTestBase {

  /**
   * Run Wycheproof MAC tests from a JSON file.
   *
   * @param resourcePath path to the Wycheproof JSON test vector file
   * @param algorithm JCE algorithm name (e.g., "HmacSHA256")
   */
  protected void runWycheproofMacTests(String resourcePath, String algorithm) throws Exception {
    JsonObject root = loadTestFile(resourcePath);

    String algorithmName = root.get("algorithm").getAsString();
    int numberOfTests = root.get("numberOfTests").getAsInt();

    LOG.info("Running {} Wycheproof test vectors for {}", numberOfTests, algorithmName);

    JsonArray testGroups = root.getAsJsonArray("testGroups");
    int passed = 0;
    int failed = 0;
    int skipped = 0;

    for (JsonElement groupElement : testGroups) {
      JsonObject group = groupElement.getAsJsonObject();
      int keySize = group.get("keySize").getAsInt();
      int tagSize = group.get("tagSize").getAsInt();

      JsonArray tests = group.getAsJsonArray("tests");
      for (JsonElement testElement : tests) {
        JsonObject test = testElement.getAsJsonObject();
        int tcId = test.get("tcId").getAsInt();
        String result = test.get("result").getAsString();

        byte[] key = net.randombit.botan.codec.HexUtils.decode(test.get("key").getAsString());
        byte[] msg = net.randombit.botan.codec.HexUtils.decode(test.get("msg").getAsString());
        byte[] tag = net.randombit.botan.codec.HexUtils.decode(test.get("tag").getAsString());

        try {
          byte[] computed = computeMac(algorithm, key, msg, tagSize);

          boolean tagsMatch = Arrays.equals(tag, computed);

          if (result.equals("valid") || result.equals("acceptable")) {
            if (tagsMatch) {
              passed++;
            } else {
              failed++;
              LOG.error("Test {} FAILED: Tag mismatch", tcId);
              printTestDetails(test);
            }
          } else if (result.equals("invalid")) {
            if (!tagsMatch) {
              passed++;
            } else {
              failed++;
              LOG.error("Test {} FAILED: Expected invalid but tags matched", tcId);
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

    logSummaryAndCheckFailures(passed, failed, skipped, numberOfTests, algorithmName);
  }

  /** Compute MAC for a message. */
  private byte[] computeMac(String algorithm, byte[] key, byte[] msg, int tagSize)
      throws Exception {
    Mac mac = Mac.getInstance(algorithm, "Botan");
    SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
    mac.init(keySpec);
    byte[] fullTag = mac.doFinal(msg);

    // Truncate if necessary
    int tagBytes = tagSize / 8;
    if (fullTag.length > tagBytes) {
      byte[] truncated = new byte[tagBytes];
      System.arraycopy(fullTag, 0, truncated, 0, tagBytes);
      return truncated;
    }

    return fullTag;
  }
}
