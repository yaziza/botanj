/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.util;

import java.util.List;
import java.util.stream.Stream;
import javax.crypto.NoSuchPaddingException;

/** Enumeration of supported padding algorithms for block ciphers. */
public enum PaddingAlgorithm {

  /** No padding. */
  NO_PADDING("NoPadding"),

  /** PKCS#5 padding. */
  PKCS5_PADDING("PKCS5"),

  /** PKCS#7 padding. */
  PKCS7_PADDING("PKCS7"),

  /** ISO 7816-4 padding. */
  One_And_Zeros("OneAndZeros"),

  /** ANSI X9.23 padding. */
  X923_PADDING("X9.23"),

  /** IP Encapsulating Security Payload (ESP) padding. */
  ESP_PADDING("ESP");

  private final String name;

  PaddingAlgorithm(String name) {
    this.name = name;
  }

  /**
   * Returns the padding algorithm matching the given name.
   *
   * <p>Supports both Botan-style names (e.g., "PKCS7", "NoPadding") and standard JCE-style names
   * with "Padding" suffix (e.g., "PKCS7Padding", "PKCS5Padding").
   *
   * @param padding the padding algorithm name
   * @return the corresponding PaddingAlgorithm
   * @throws NoSuchPaddingException if the algorithm is not supported
   */
  public static PaddingAlgorithm fromName(String padding) throws NoSuchPaddingException {
    List<PaddingAlgorithm> algorithm =
        Stream.of(PaddingAlgorithm.values()).filter(p -> padding.contains(p.name)).toList();

    if (algorithm.isEmpty()) {
      throw new NoSuchPaddingException("Padding algorithm not supported: " + padding);
    }

    return getNormalized(algorithm.get(0));
  }

  /**
   * Most Java providers( e.g. SUN and Bouncy Castle) indicates PKCS5 where PKCS7 padding should be
   * used. This method is for supporting such legacy systems migrating to Botanj and to enable
   * testing against other providers.
   *
   * @param padding the {@link PaddingAlgorithm} to be normalized
   * @return the normalized {@link PaddingAlgorithm}.
   */
  private static PaddingAlgorithm getNormalized(PaddingAlgorithm padding) {
    return (padding == PKCS5_PADDING) ? PKCS7_PADDING : padding;
  }

  /**
   * Gets the name of this padding algorithm as used by Botan.
   *
   * @return the padding algorithm name
   */
  public String getName() {
    return name;
  }
}
