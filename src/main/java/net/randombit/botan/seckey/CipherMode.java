/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey;

import net.randombit.botan.util.PaddingAlgorithm;

public enum CipherMode {

    /**
     * Cipher block chaining mode.
     */
    CBC(PaddingAlgorithm.values()),

    /**
     * Cipher feedback mode.
     */
    CFB(PaddingAlgorithm.NO_PADDING),

    /**
     * Counter mode.
     */
    CTR(PaddingAlgorithm.NO_PADDING),

    /**
     * Output feedback mode.
     */
    OFB(PaddingAlgorithm.NO_PADDING),

    /**
     * Galois counter mode.
     */
    GCM(PaddingAlgorithm.NO_PADDING),

    /**
     * Counter with CBC-MAC
     */
    CCM(PaddingAlgorithm.NO_PADDING),

    /**
     * Synthetic Initialization Vector.
     */
    SIV(PaddingAlgorithm.NO_PADDING),

    /**
     * Encrypt-then-authenticate-then-translate mode.
     */
    EAX(PaddingAlgorithm.NO_PADDING),

    /**
     * Offset Codebook Mode.
     */
    OCB(PaddingAlgorithm.NO_PADDING);

    private final PaddingAlgorithm[] supportedPadding;

    CipherMode(PaddingAlgorithm... algorithms) {
        this.supportedPadding = algorithms;
    }

    public boolean isPaddingSupported(PaddingAlgorithm algorithm) {
        for (PaddingAlgorithm padding : supportedPadding) {
            if (padding == algorithm) {
                return true;
            }
        }

        return false;
    }

}
