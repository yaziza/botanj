/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan;

import jnr.ffi.Pointer;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;

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
    long botan_ffi_api_version();

    /**
     * Returns the version of the currently supported FFI API. This is
     * expressed in the form YYYYMMDD of the release date of this version
     * of the API.
     *
     * @param apiVersion supported API version
     * @return 0 if the given API version is supported
     */
    int botan_ffi_supports_api(long apiVersion);

    /**
     * Returns a free-form version string, e.g., 2.0.0
     *
     * @return {@link String} version
     */
    String botan_version_string();

    /**
     * @return the major version of the library
     */
    long botan_version_major();

    /**
     * @return the minor version of the library
     */
    long botan_version_minor();

    /**
     * @return the patch version of the library
     */
    long botan_version_patch();

    /**
     * @return the date this version was released as an integer,
     * or 0 if an unreleased version
     */
    long botan_version_datestamp();

    /**
     * Performs hex encoding.
     *
     * @param input       is some binary data
     * @param inputLength length of x in bytes
     * @param output      an array of at least x*2 bytes
     * @param flags       flags out be upper or lower case?
     * @return 0 on success, a negative value on failure
     */
    int botan_hex_encode(@In byte[] input, @In long inputLength, @Out byte[] output, @In long flags);

    /**
     * Performs hex decoding.
     *
     * @param input        a string of hex chars (whitespace is ignored)
     * @param inputLength  the length of the input
     * @param output       the output buffer should be at least strlen(input)/2 bytes
     * @param outputLength the size of the output
     * @return 0 on success, a negative value on failure
     */
    int botan_hex_decode(@In byte[] input, @In long inputLength, @Out byte[] output,
                         @Out NativeLongByReference outputLength);

    /**
     * Performs base64 encoding.
     *
     * @param input        the input buffer
     * @param inputLength  the length of the input
     * @param output       the output buffer
     * @param outputLength the size of the output
     * @return 0 on success, a negative value on failure
     */
    int botan_base64_encode(@In byte[] input, @In long inputLength, @Out byte[] output,
                            @Out NativeLongByReference outputLength);

    /**
     * Performs base64 decoding.
     *
     * @param input        the input buffer
     * @param inputLength  the length of the input
     * @param output       the output buffer
     * @param outputLength the size of the output
     * @return 0 on success, a negative value on failure
     */
    int botan_base64_decode(@In String input, @In long inputLength, @Out byte[] output,
                            @Out NativeLongByReference outputLength);

    /**
     * Initializes a hash function object.
     *
     * @param hash     hash object
     * @param hashName name of the hash function, e.g., "SHA-384"
     * @param flags    should be 0 in current API revision, all other uses are reserved
     *                 and return BOTAN_FFI_ERROR_BAD_FLAG
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_init(PointerByReference hash, @In String hashName, @In long flags);

    /**
     * Copy the state of a hash function object
     *
     * @param dest   destination hash object
     * @param source source hash object
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_copy_state(PointerByReference dest, Pointer source);

    /**
     * Writes the output length of the hash function to *output_length
     *
     * @param hash   hash object
     * @param length output buffer to hold the hash function output length
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_output_length(Pointer hash, @Out NativeLongByReference length);

    /**
     * Writes the block size of the hash function to *block_size
     *
     * @param hash hash object
     * @param size output buffer to hold the hash function output length
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_block_size(Pointer hash, @Out NativeLongByReference size);

    /**
     * Send more input to the hash function
     *
     * @param hash   hash object
     * @param input  input buffer
     * @param length number of bytes to read from the input buffer
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_update(Pointer hash, @In byte[] input, @In long length);

    /**
     * Finalizes the hash computation and writes the output to
     * out[0:botan_hash_output_length()] then reinitializes for computing
     * another digest as if botan_hash_clear had been called.
     *
     * @param hash hash object
     * @param out  output buffer
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_final(Pointer hash, @Out byte[] out);

    /**
     * Reinitializes the state of the hash computation. A hash can
     * be computed (with update/final) immediately.
     *
     * @param hash hash object
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_clear(Pointer hash);

    /**
     * Frees all resources of the hash object.
     *
     * @param hash hash object
     * @return 0 if success, error if invalid object handle
     */
    //TODO: do we really need this ?
    int botan_hash_destroy(Pointer hash);

    /**
     * Get the name of this hash function
     *
     * @param hash   the object to read
     * @param name   output buffer
     * @param length on input, the length of buffer, on success the number of bytes written
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_name(Pointer hash, @In @Out byte[] name, @In @Out NativeLongByReference length);

    /**
     * Initializes a message authentication code object.
     *
     * @param mac   mac object
     * @param name  name of the hash function, e.g., "HMAC(SHA-384)"
     * @param flags should be 0 in current API revision, all other uses are reserved
     *              and return a negative value (error code)
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_init(PointerByReference mac, @In String name, @In long flags);

    /**
     * Writes the output length of the message authentication code to *output_length.
     *
     * @param mac    mac object
     * @param length output buffer to hold the MAC output length
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_output_length(Pointer mac, @Out NativeLongByReference length);

    /**
     * Sets the key on the MAC.
     *
     * @param mac    mac object
     * @param key    buffer holding the key
     * @param length size of the key buffer in bytes
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_set_key(Pointer mac, @In byte[] key, @In long length);

    /**
     * Sends more input to the message authentication code.
     *
     * @param mac    mac object
     * @param buffer input buffer
     * @param length number of bytes to read from the input buffer
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_update(Pointer mac, @In byte[] buffer, @In long length);

    /**
     * Finalizes the MAC computation and writes the output to
     * out[0:botan_mac_output_length()] then reinitializes for computing
     * another MAC as if botan_mac_clear had been called.
     *
     * @param mac mac object
     * @param out output buffer
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_final(Pointer mac, @Out byte[] out);

    /**
     * Reinitializes the state of the MAC computation. A MAC can
     * be computed (with update/final) immediately.
     *
     * @param mac mac object
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_clear(Pointer mac);

    /**
     * Frees all resources of the MAC object
     *
     * @param mac mac object
     * @return 0 if success, error if invalid object handle
     */
    int botan_mac_destroy(Pointer mac);

    /**
     * Gets the name of this MAC
     *
     * @param mac    the object to read
     * @param name   output buffer
     * @param length on input, the length of buffer, on success the number of bytes written
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_name(Pointer mac, @In @Out byte[] name, @In @Out NativeLongByReference length);

}
