/*
 * (C) 2025 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.wycheproof;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Wycheproof test vectors for HmacSHA224.
 */
@DisplayName("Wycheproof HmacSHA224 tests")
public class HmacSHA224WycheproofTest extends WycheproofMacTest {

    @Test
    @DisplayName("Run Wycheproof HmacSHA224 test vectors")
    void testHmacSHA224Wycheproof() throws Exception {
        runWycheproofMacTests("/wycheproof/hmac_sha224_test.json", "HmacSHA224");
    }
}
