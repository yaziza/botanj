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
 * Wycheproof test vectors for AES-GCM.
 *
 * <p>These tests verify the implementation against known attack vectors and edge cases
 * identified by Google's Project Wycheproof.
 *
 * @see <a href="https://github.com/C2SP/wycheproof">Wycheproof Repository</a>
 */
@DisplayName("Wycheproof AES-GCM tests")
public class AesGcmWycheproofTest extends WycheproofAeadTest {

    @Test
    @DisplayName("Run Wycheproof AES-GCM test vectors")
    void testAesGcmWycheproof() throws Exception {
        runWycheproofAeadTests("/wycheproof/aes_gcm_test.json", "AES/GCM/NoPadding");
    }

}
