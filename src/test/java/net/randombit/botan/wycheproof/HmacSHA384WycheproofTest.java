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

/** Wycheproof test vectors for HmacSHA384. */
@DisplayName("Wycheproof HmacSHA384 tests")
public class HmacSHA384WycheproofTest extends WycheproofMacTest {

  @Test
  @DisplayName("Run Wycheproof HmacSHA384 test vectors")
  void testHmacSHA384Wycheproof() throws Exception {
    runWycheproofMacTests("/wycheproof/hmac_sha384_test.json", "HmacSHA384");
  }
}
