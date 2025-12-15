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

/** Wycheproof test vectors for HmacSHA1. */
@DisplayName("Wycheproof HmacSHA1 tests")
public class HmacSHA1WycheproofTest extends WycheproofMacTest {

  @Test
  @DisplayName("Run Wycheproof HmacSHA1 test vectors")
  void testHmacSHA1Wycheproof() throws Exception {
    runWycheproofMacTests("/wycheproof/hmac_sha1_test.json", "HmacSHA1");
  }
}
