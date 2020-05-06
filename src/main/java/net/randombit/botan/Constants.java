/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan;

public final class Constants {

    /**
     * Calling botan_cipher_update() for sending more input.
     */
    public static final int BOTAN_UPDATE_FLAG = 0;

    /**
     * Calling botan_cipher_update() for finishing cipher operation.
     */
    public static final int BOTAN_DO_FINAL_FLAG = 1;

    /**
     * Holds an empty array of bytes
     */
    public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    private Constants() {
        // Not meant to be instantiated
    }

}
