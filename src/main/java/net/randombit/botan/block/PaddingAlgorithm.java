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

    NO_PADDING("NoPadding"),
    PKCS5_PADDING("PKCS5"),
    PKCS7_PADDING("PKCS7"),
    One_And_Zeros("OneAndZeros"),
    X923_PADDING("X9.23"),
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
