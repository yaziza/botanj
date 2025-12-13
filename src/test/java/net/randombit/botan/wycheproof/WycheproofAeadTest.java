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

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.HexFormat;
import net.randombit.botan.spec.AeadParameterSpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Base class for Wycheproof AEAD test vectors.
 *
 * <p>Wycheproof is a project by Google to test crypto libraries against known attacks.
 * These tests use the official Wycheproof test vectors from:
 * https://github.com/C2SP/wycheproof
 */
public abstract class WycheproofAeadTest {

    private static final HexFormat HEX = HexFormat.of();

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
    }

    /**
     * Run Wycheproof AEAD tests from a JSON file.
     *
     * @param resourcePath path to the Wycheproof JSON test vector file
     * @param transformation JCE transformation string (e.g., "AES/GCM/NoPadding")
     */
    protected void runWycheproofAeadTests(String resourcePath, String transformation) throws Exception {
        InputStream is = getClass().getResourceAsStream(resourcePath);
        if (is == null) {
            fail("Could not find test vector file: " + resourcePath);
        }

        Gson gson = new Gson();
        JsonObject root = gson.fromJson(new InputStreamReader(is, StandardCharsets.UTF_8), JsonObject.class);

        String algorithm = root.get("algorithm").getAsString();
        int numberOfTests = root.get("numberOfTests").getAsInt();

        System.out.println("Running " + numberOfTests + " Wycheproof test vectors for " + algorithm);

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

                byte[] key = HEX.parseHex(test.get("key").getAsString());
                byte[] iv = HEX.parseHex(test.get("iv").getAsString());
                byte[] aad = HEX.parseHex(test.get("aad").getAsString());
                byte[] msg = HEX.parseHex(test.get("msg").getAsString());
                byte[] ct = HEX.parseHex(test.get("ct").getAsString());
                byte[] tag = HEX.parseHex(test.get("tag").getAsString());

                // Check if we should skip this test
                if (shouldSkipTest(keySize, ivSize, tagSize, test)) {
                    skipped++;
                    continue;
                }

                try {
                    boolean testResult = runAeadTest(transformation, key, iv, aad, msg, ct, tag, tagSize);

                    if (result.equals("valid") || result.equals("acceptable")) {
                        if (testResult) {
                            passed++;
                        } else {
                            failed++;
                            System.err.println("Test " + tcId + " FAILED: Expected valid/acceptable but decryption failed");
                            printTestDetails(test);
                        }
                    } else if (result.equals("invalid")) {
                        if (!testResult) {
                            passed++;
                        } else {
                            failed++;
                            System.err.println("Test " + tcId + " FAILED: Expected invalid but decryption succeeded");
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
            fail(failed + " Wycheproof tests failed for " + algorithm);
        }
    }

    /**
     * Run a single AEAD test.
     *
     * @return true if decryption succeeded and matched expected plaintext, false otherwise
     */
    private boolean runAeadTest(String transformation, byte[] key, byte[] iv, byte[] aad,
                                byte[] msg, byte[] ct, byte[] tag, int tagSize) {
        try {
            // Combine ciphertext and tag
            byte[] ctWithTag = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, ctWithTag, 0, ct.length);
            System.arraycopy(tag, 0, ctWithTag, ct.length, tag.length);

            Cipher cipher = Cipher.getInstance(transformation, "Botan");

            // Determine algorithm from transformation
            String algorithm = transformation.split("/")[0];
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);

            // Create appropriate parameter spec based on cipher type
            java.security.spec.AlgorithmParameterSpec params = createParameterSpec(transformation, iv, tagSize);

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

    /**
     * Create the appropriate parameter spec for the cipher type.
     */
    private java.security.spec.AlgorithmParameterSpec createParameterSpec(String transformation, byte[] iv, int tagSize) {
        String mode = transformation.toUpperCase();

        if (mode.contains("GCM")) {
            return new GCMParameterSpec(tagSize, iv);
        } else if (mode.contains("CCM") || mode.contains("EAX") || mode.contains("OCB") || mode.contains("SIV")) {
            // CCM, EAX, OCB, SIV need tag size - use AeadParameterSpec
            return new AeadParameterSpec(iv, tagSize);
        } else if (mode.contains("CHACHA20")) {
            // ChaCha20-Poly1305 and XChaCha20-Poly1305 use IvParameterSpec
            // ChaCha20: 96-bit nonce, XChaCha20: 192-bit nonce
            return new IvParameterSpec(iv);
        } else {
            // Default to GCMParameterSpec for unknown modes
            return new GCMParameterSpec(tagSize, iv);
        }
    }

    /**
     * Determine if a test should be skipped based on parameters.
     * Subclasses can override to skip tests for unsupported configurations.
     */
    protected boolean shouldSkipTest(int keySize, int ivSize, int tagSize, JsonObject test) {
        // Default: don't skip any tests
        return false;
    }

    private void printTestDetails(JsonObject test) {
        System.err.println("  Comment: " + test.get("comment").getAsString());
        System.err.println("  Flags: " + test.get("flags").toString());
    }
}
