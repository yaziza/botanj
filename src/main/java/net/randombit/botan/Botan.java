/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan;

import java.security.GeneralSecurityException;

import com.sun.jdi.NativeMethodException;
import jnr.ffi.LibraryLoader;

public final class Botan {

    private static final String LIB_NAME = "botan-2";

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
                        result = NATIVE = LibraryLoader.create(BotanNative.class).load(LIB_NAME);
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

    /**
     * Checks whether a native lib call was successful.
     *
     * @param result int result from calling botan native
     * @throws {@link GeneralSecurityException} in case of error
     */
    public static void checkNativeCall(int result, String method) throws NativeMethodException {
        if (result != 0) {
            String description = NATIVE.botan_error_description(result);
            throw new NativeMethodException(method + ": " + description);
        }
    }

}
