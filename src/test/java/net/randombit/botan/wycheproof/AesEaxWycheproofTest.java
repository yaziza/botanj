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
 * Wycheproof test vectors for AES-EAX.
 */
@DisplayName("Wycheproof AES-EAX tests")
public class AesEaxWycheproofTest extends WycheproofAeadTest {

    @Test
    @DisplayName("Run Wycheproof AES-EAX test vectors")
    void testAesEaxWycheproof() throws Exception {
        runWycheproofAeadTests("/wycheproof/aes_eax_test.json", "AES/EAX/NoPadding");
    }

}
