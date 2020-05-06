/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.block;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.NoSuchPaddingException;

public enum PaddingAlgorithm {

    /**
     * No padding.
     */
    NO_PADDING("NoPadding"),

    /**
     * PKCS5.
     */
    PKCS5_PADDING("PKCS5"),

    /**
     * PKCS7.
     */
    PKCS7_PADDING("PKCS7"),

    /**
     * ISO 7816-4 Padding.
     */
    One_And_Zeros("OneAndZeros"),

    /**
     * ANSI X9.23 Padding.
     */
    X923_PADDING("X9.23"),

    /**
     * IP Encapsulating Security Payload (ESP) pading.
     */
    ESP_PADDING("ESP");

    private final String name;

    PaddingAlgorithm(String name) {
        this.name = name;
    }

    public static PaddingAlgorithm fromName(String name) throws NoSuchPaddingException {
        List<PaddingAlgorithm> algorithm = Stream.of(PaddingAlgorithm.values())
                .filter(p -> p.name.equalsIgnoreCase(name))
                .collect(Collectors.toList());

        if (algorithm.isEmpty()) {
            throw new NoSuchPaddingException("Padding algorithm not supported: " + name);
        }

        return getNormalized(algorithm.get(0));
    }

    private static PaddingAlgorithm getNormalized(PaddingAlgorithm padding) {
        return (padding == PKCS5_PADDING) ? PKCS7_PADDING : padding;
    }

    public String getName() {
        return name;
    }

}