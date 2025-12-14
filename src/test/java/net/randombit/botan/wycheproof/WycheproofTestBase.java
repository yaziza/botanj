/*
 * (C) 2025 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.wycheproof;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import net.randombit.botan.BotanProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Base class for all Wycheproof test vectors.
 *
 * <p>Wycheproof is a project to test crypto libraries against known attacks.
 * These tests use the official Wycheproof test vectors from:
 * https://github.com/C2SP/wycheproof
 */
public abstract class WycheproofTestBase {

    protected static final Logger LOG = LogManager.getLogger(WycheproofTestBase.class);

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
    }

    /**
     * Load and parse a Wycheproof JSON test file.
     *
     * @param resourcePath path to the Wycheproof JSON test vector file
     * @return parsed JSON root object
     */
    protected JsonObject loadTestFile(String resourcePath) {
        InputStream is = getClass().getResourceAsStream(resourcePath);
        if (is == null) {
            fail("Could not find test vector file: " + resourcePath);
        }

        Gson gson = new Gson();
        return gson.fromJson(new InputStreamReader(is, StandardCharsets.UTF_8), JsonObject.class);
    }

    /**
     * Log test summary and fail if any tests failed.
     *
     * @param passed number of tests that passed
     * @param failed number of tests that failed
     * @param skipped number of tests that were skipped
     * @param numberOfTests total number of tests
     * @param algorithm algorithm name
     */
    protected void logSummaryAndCheckFailures(int passed, int failed, int skipped, int numberOfTests, String algorithm) {
        LOG.info("Results: {} passed, {} failed, {} skipped out of {}", passed, failed, skipped, numberOfTests);

        if (failed > 0) {
            fail(failed + " Wycheproof tests failed for " + algorithm);
        }
    }

    /**
     * Print details of a failed test.
     *
     * @param test the test case JSON object
     */
    protected void printTestDetails(JsonObject test) {
        LOG.error("  Comment: {}", test.get("comment").getAsString());
        LOG.error("  Flags: {}", test.get("flags").toString());
    }
}
