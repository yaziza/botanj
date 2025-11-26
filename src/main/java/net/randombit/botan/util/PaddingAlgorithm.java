/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.util;

import javax.crypto.NoSuchPaddingException;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Enumeration of supported padding algorithms for block ciphers.
 */
public enum PaddingAlgorithm {

    /**
     * No padding.
     */
    NO_PADDING("NoPadding"),

    /**
     * PKCS#5 padding.
     */
    PKCS5_PADDING("PKCS5"),

    /**
     * PKCS#7 padding.
     */
    PKCS7_PADDING("PKCS7"),

    /**
     * ISO 7816-4 padding.
     */
    One_And_Zeros("OneAndZeros"),

    /**
     * ANSI X9.23 padding.
     */
    X923_PADDING("X9.23"),

    /**
     * IP Encapsulating Security Payload (ESP) padding.
     */
    ESP_PADDING("ESP");

    private final String name;

    PaddingAlgorithm(String name) {
        this.name = name;
    }

    /**
     * Returns the padding algorithm matching the given name.
     *
     * @param name the padding algorithm name
     * @return the corresponding PaddingAlgorithm
     * @throws NoSuchPaddingException if the algorithm is not supported
     */
    public static PaddingAlgorithm fromName(String name) throws NoSuchPaddingException {
        List<PaddingAlgorithm> algorithm = Stream.of(PaddingAlgorithm.values())
                .filter(p -> p.name.equalsIgnoreCase(name))
                .collect(Collectors.toList());

        if (algorithm.isEmpty()) {
            throw new NoSuchPaddingException("Padding algorithm not supported: " + name);
        }

        return getNormalized(algorithm.get(0));
    }

    /**
     * Most Java providers( e.g. SUN and Bouncy Castle) indicates PKCS5
     * where PKCS7 padding should be used. This method is for supporting such
     * legacy systems migrating to Botanj and to enable testing against other
     * providers.
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
