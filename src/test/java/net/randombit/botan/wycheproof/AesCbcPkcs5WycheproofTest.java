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
 * Wycheproof test vectors for AES-CBC with PKCS5 padding.
 */
@DisplayName("Wycheproof AES-CBC-PKCS5 tests")
public class AesCbcPkcs5WycheproofTest extends WycheproofCipherTest {

    @Test
    @DisplayName("Run Wycheproof AES-CBC-PKCS5 test vectors")
    void testAesCbcPkcs5Wycheproof() throws Exception {
        runWycheproofCipherTests("/wycheproof/aes_cbc_pkcs5_test.json", "AES/CBC/PKCS5Padding");
    }
}
