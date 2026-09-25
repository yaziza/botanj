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

/** Wycheproof test vectors for HMAC-SHA3-256. */
@DisplayName("Wycheproof HMAC-SHA3-256 tests")
public class HmacSHA3256WycheproofTest extends WycheproofMacTest {

  @Test
  @DisplayName("Run Wycheproof HMAC-SHA3-256 test vectors")
  void testHmacSha3256Wycheproof() throws Exception {
    runWycheproofMacTests("/wycheproof/hmac_sha3_256_test.json", "HmacSHA3-256");
  }
}
