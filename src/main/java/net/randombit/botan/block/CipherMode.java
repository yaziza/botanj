/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.block;

public enum CipherMode {

    /**
     * Galois counter mode.
     */
    GCM(true, PaddingAlgorithm.NO_PADDING),

    /**
     * Synthetic Initialization Vector.
     */
    SIV(true, PaddingAlgorithm.NO_PADDING),

    /**
     * Encrypt-then-authenticate-then-translate mode.
     */
    EAX(true, PaddingAlgorithm.NO_PADDING),

    /**
     * Counter mode.
     */
    CTR(false, PaddingAlgorithm.NO_PADDING),

    /**
     * Cipher block chaining mode.
     */
    CBC(false, PaddingAlgorithm.values()),

    /**
     * Cipher feedback mode.
     */
    CFB(false, PaddingAlgorithm.NO_PADDING),

    /**
     * Output feedback mode.
     */
    OFB(false, PaddingAlgorithm.NO_PADDING);

    private final PaddingAlgorithm[] supportedPadding;

    private final boolean isAuthenticated;

    CipherMode(boolean isAuthenticated, PaddingAlgorithm... algorithms) {
        this.isAuthenticated = isAuthenticated;
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

    public boolean isAuthenticated() {
        return isAuthenticated;
    }

}
