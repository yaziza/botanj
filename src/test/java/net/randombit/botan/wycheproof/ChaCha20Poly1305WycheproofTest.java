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
 * Wycheproof test vectors for ChaCha20-Poly1305.
 */
@DisplayName("Wycheproof ChaCha20-Poly1305 tests")
public class ChaCha20Poly1305WycheproofTest extends WycheproofAeadTest {

    @Test
    @DisplayName("Run Wycheproof ChaCha20-Poly1305 test vectors")
    void testChaCha20Poly1305Wycheproof() throws Exception {
        runWycheproofAeadTests("/wycheproof/chacha20_poly1305_test.json", "ChaCha20-Poly1305");
    }

}
