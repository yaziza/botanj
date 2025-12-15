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

/** Wycheproof test vectors for HmacSHA512. */
@DisplayName("Wycheproof HmacSHA512 tests")
public class HmacSHA512WycheproofTest extends WycheproofMacTest {

  @Test
  @DisplayName("Run Wycheproof HmacSHA512 test vectors")
  void testHmacSHA512Wycheproof() throws Exception {
    runWycheproofMacTests("/wycheproof/hmac_sha512_test.json", "HmacSHA512");
  }
}
