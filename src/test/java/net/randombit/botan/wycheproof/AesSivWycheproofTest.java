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
 * Wycheproof test vectors for AES-SIV (Synthetic IV).
 */
@DisplayName("Wycheproof AES-SIV tests")
public class AesSivWycheproofTest extends WycheproofAeadTest {

    @Test
    @DisplayName("Run Wycheproof AES-SIV test vectors")
    void testAesSivWycheproof() throws Exception {
        runWycheproofAeadTests("/wycheproof/aead_aes_siv_cmac_test.json", "AES/SIV/NoPadding");
    }

}
