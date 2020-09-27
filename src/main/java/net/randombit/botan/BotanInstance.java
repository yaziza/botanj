/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan;

import com.sun.jdi.NativeMethodException;
import jnr.ffi.LibraryLoader;

public final class BotanInstance {

    private static final String LIB_NAME = "botan-2";

    private static volatile BotanNativeInterface NATIVE;
    private static UnsatisfiedLinkError loadError;

    private BotanInstance() {
        // Not meant to be instantiated
    }

    /**
     * Returns a singleton instance of the {@link BotanNativeInterface} library.
     *
     * @return {@link BotanNativeInterface} singleton instance
     */
    public static BotanNativeInterface singleton() {
        BotanNativeInterface result = NATIVE;
        if (result == null) {
            synchronized (BotanInstance.class) {
                result = NATIVE;
                if (result == null) {
                    try {
                        result = NATIVE = LibraryLoader.create(BotanNativeInterface.class).load(LIB_NAME);
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
     * Checks whether or not the native library was successfully loaded.
     *
     * @throws {@link UnsatisfiedLinkError} that was encountered while attempting to load the library.
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
     * @throws {@link NativeMethodException} in case of error
     */
    public static void checkNativeCall(int result, String method) throws NativeMethodException {
        if (result != 0) {
            String description = NATIVE.botan_error_description(result);
            throw new NativeMethodException(method + ": " + description);
        }
    }

}
