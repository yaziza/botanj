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

/** Wycheproof test vectors for HMAC-SHA3-224. */
@DisplayName("Wycheproof HMAC-SHA3-224 tests")
public class HmacSHA3224WycheproofTest extends WycheproofMacTest {

  @Test
  @DisplayName("Run Wycheproof HMAC-SHA3-224 test vectors")
  void testHmacSha3224Wycheproof() throws Exception {
    runWycheproofMacTests("/wycheproof/hmac_sha3_224_test.json", "HmacSHA3-224");
  }
}
