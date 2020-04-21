/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan;

public interface BotanNative {

    /**
     * Converts an error code into a string. Returns "Unknown error"
     * if the error code is not a known one.
     *
     * @param err error code
     * @return {@link String} description
     */
    String botan_error_description(int err);

    /**
     * Returns the version of the currently supported FFI API. This is
     * expressed in the form YYYYMMDD of the release date of this version
     * of the API.
     *
     * @return api version
     */
    int botan_ffi_api_version();

    /**
     * Returns the version of the currently supported FFI API. This is
     * expressed in the form YYYYMMDD of the release date of this version
     * of the API.
     *
     * @param apiVersion supported API version
     * @return 0 if the given API version is supported
     */
    int botan_ffi_supports_api(int apiVersion);

    /**
     * Returns a free-form version string, e.g., 2.0.0
     *
     * @return {@link String} version
     */
    String botan_version_string();

    /**
     * @return the major version of the library
     */
    int botan_version_major();

    /**
     * @return the minor version of the library
     */
    int botan_version_minor();

    /**
     * @return the patch version of the library
     */
    int botan_version_patch();

    /**
     * @return the date this version was released as an integer,
     * or 0 if an unreleased version
     */
    int botan_version_datestamp();

}
