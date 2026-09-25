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

/** Wycheproof test vectors for HMAC-SHA256. */
@DisplayName("Wycheproof HMAC-SHA256 tests")
public class HmacSha256WycheproofTest extends WycheproofMacTest {

  @Test
  @DisplayName("Run Wycheproof HMAC-SHA256 test vectors")
  void testHmacSha256Wycheproof() throws Exception {
    runWycheproofMacTests("/wycheproof/hmac_sha256_test.json", "HmacSHA256");
  }
}
