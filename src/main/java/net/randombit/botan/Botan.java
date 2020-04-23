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

    private static final String RELATIVE_LIB_PATH = "/native/lib/libbotan-2.dylib";

    private static volatile BotanNative NATIVE;
    private static UnsatisfiedLinkError loadError;

    private Botan() {
        // Not meant to be instantiated
    }

    /**
     * Returns a singleton instance of the {@link BotanNative} library.
     *
     * @return {@link BotanNative} singleton instance
     */
    public static BotanNative singleton() {
        BotanNative result = NATIVE;
        if (result == null) {
            synchronized (Botan.class) {
                result = NATIVE;
                if (result == null) {
                    try {
                        String libPath = Botan.class.getResource(RELATIVE_LIB_PATH).getPath();
                        result = NATIVE = LibraryLoader.create(BotanNative.class).load(libPath);
                    } catch (UnsatisfiedLinkError t) {
                        // Don't rethrow the error, so that we can later on interrogate the
                        // value of loadError.
                        loadError = t;
                    }
                }
            }
        }

        return result;
    }

    /**
     * Checks whether or not the native library was successfully loaded. If not, throws the
     * {@link UnsatisfiedLinkError} that was encountered while attempting to load the library.
     */
    public static void checkAvailability() {
        if (loadError != null) {
            throw loadError;
        }
    }

}
