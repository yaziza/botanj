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

/** Wycheproof test vectors for XChaCha20-Poly1305. */
@DisplayName("Wycheproof XChaCha20-Poly1305 tests")
public class XChaCha20Poly1305WycheproofTest extends WycheproofAeadTest {

  @Test
  @DisplayName("Run Wycheproof XChaCha20-Poly1305 test vectors")
  void testXChaCha20Poly1305Wycheproof() throws Exception {
    runWycheproofAeadTests("/wycheproof/xchacha20_poly1305_test.json", "XChaCha20-Poly1305");
  }
}
