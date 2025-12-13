/*
 * (C) 2024 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.wycheproof;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import net.randombit.botan.BotanProvider;
import org.junit.jupiter.api.BeforeAll;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Base class for Wycheproof MAC test vectors.
 */
public abstract class WycheproofMacTest {

    private static final HexFormat HEX = HexFormat.of();

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
    }

    /**
     * Run Wycheproof MAC tests from a JSON file.
     *
     * @param resourcePath path to the Wycheproof JSON test vector file
     * @param algorithm JCE algorithm name (e.g., "HmacSHA256")
     */
    protected void runWycheproofMacTests(String resourcePath, String algorithm) throws Exception {
        InputStream is = getClass().getResourceAsStream(resourcePath);
        if (is == null) {
            fail("Could not find test vector file: " + resourcePath);
        }

        Gson gson = new Gson();
        JsonObject root = gson.fromJson(new InputStreamReader(is, StandardCharsets.UTF_8), JsonObject.class);

        String algorithmName = root.get("algorithm").getAsString();
        int numberOfTests = root.get("numberOfTests").getAsInt();

        System.out.println("Running " + numberOfTests + " Wycheproof test vectors for " + algorithmName);

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

                byte[] key = HEX.parseHex(test.get("key").getAsString());
                byte[] msg = HEX.parseHex(test.get("msg").getAsString());
                byte[] tag = HEX.parseHex(test.get("tag").getAsString());

                if (shouldSkipTest(keySize, tagSize, test)) {
                    skipped++;
                    continue;
                }

                try {
                    byte[] computed = computeMac(algorithm, key, msg, tagSize);

                    boolean tagsMatch = Arrays.equals(tag, computed);

                    if (result.equals("valid") || result.equals("acceptable")) {
                        if (tagsMatch) {
                            passed++;
                        } else {
                            failed++;
                            System.err.println("Test " + tcId + " FAILED: Tag mismatch");
                            printTestDetails(test);
                        }
                    } else if (result.equals("invalid")) {
                        if (!tagsMatch) {
                            passed++;
                        } else {
                            failed++;
                            System.err.println("Test " + tcId + " FAILED: Expected invalid but tags matched");
                            printTestDetails(test);
                        }
                    }
                } catch (Exception e) {
                    if (result.equals("invalid")) {
                        passed++;
                    } else {
                        failed++;
                        System.err.println("Test " + tcId + " FAILED with exception: " + e.getMessage());
                        printTestDetails(test);
                    }
                }
            }
        }

        System.out.println("Results: " + passed + " passed, " + failed + " failed, " + skipped + " skipped out of " + numberOfTests);

        if (failed > 0) {
            fail(failed + " Wycheproof tests failed for " + algorithmName);
        }
    }

    /**
     * Compute MAC for a message.
     */
    private byte[] computeMac(String algorithm, byte[] key, byte[] msg, int tagSize) throws Exception {
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

    /**
     * Determine if a test should be skipped.
     */
    protected boolean shouldSkipTest(int keySize, int tagSize, JsonObject test) {
        return false;
    }

    private void printTestDetails(JsonObject test) {
        System.err.println("  Comment: " + test.get("comment").getAsString());
        System.err.println("  Flags: " + test.get("flags").toString());
    }
}
