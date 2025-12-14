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
 * Wycheproof test vectors for AES-CMAC.
 */
@DisplayName("Wycheproof AES-CMAC tests")
public class AesCmacWycheproofTest extends WycheproofMacTest {

    @Test
    @DisplayName("Run Wycheproof AES-CMAC test vectors")
    void testAesCmacWycheproof() throws Exception {
        runWycheproofMacTests("/wycheproof/aes_cmac_test.json", "AESCMAC");
    }
}
