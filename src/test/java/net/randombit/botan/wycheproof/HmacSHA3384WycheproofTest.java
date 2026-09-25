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

/** Wycheproof test vectors for HMAC-SHA3-384. */
@DisplayName("Wycheproof HMAC-SHA3-384 tests")
public class HmacSHA3384WycheproofTest extends WycheproofMacTest {

  @Test
  @DisplayName("Run Wycheproof HMAC-SHA3-384 test vectors")
  void testHmacSha3384Wycheproof() throws Exception {
    runWycheproofMacTests("/wycheproof/hmac_sha3_384_test.json", "HmacSHA3-384");
  }
}
