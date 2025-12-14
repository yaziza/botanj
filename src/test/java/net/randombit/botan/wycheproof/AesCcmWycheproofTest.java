/*
 * (C) 2025 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.wycheproof;

import com.google.gson.JsonObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Wycheproof test vectors for AES-CCM.
 */
@DisplayName("Wycheproof AES-CCM tests")
public class AesCcmWycheproofTest extends WycheproofAeadTest {

    @Test
    @DisplayName("Run Wycheproof AES-CCM test vectors")
    void testAesCcmWycheproof() throws Exception {
        runWycheproofAeadTests("/wycheproof/aes_ccm_test.json", "AES/CCM/NoPadding");
    }

}
