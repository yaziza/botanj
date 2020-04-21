/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan;

import jnr.ffi.LibraryLoader;

public final class Botan {

    private static final String BOTAN_LIB_PATH = "/Users/carlos/botan/lib/libbotan-2.dylib";

    private static volatile BotanNative singleton;

    public static BotanNative getInstance() {
        BotanNative result = singleton;

        if (result == null) {
            synchronized (Botan.class) {
                result = singleton;
                if (result == null) {
                    result = singleton = loadNativeLib();
                }
            }
        }

        return result;
    }

    private static BotanNative loadNativeLib() {
        return LibraryLoader.create(BotanNative.class).load(BOTAN_LIB_PATH);
    }

}
