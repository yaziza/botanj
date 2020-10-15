/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.jnr;

import jnr.ffi.Pointer;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;

public interface BotanLibrary {

    /**
     * Converts an error code into a string. Returns "Unknown error"
     * if the error code is not a known one.
     *
     * @param err error code
     * @return {@link String} description
     */
    String botan_error_description(@In int err);

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
     * Performs hex encoding.
     *
     * @param input       is some binary data
     * @param inputLength length of x in bytes
     * @param output      an array of at least x*2 bytes
     * @param flags       output be upper or lower case?
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
    int botan_hash_init(@Out PointerByReference hash, @In String hashName, @In long flags);

    /**
     * Copy the state of a hash function object.
     *
     * @param dest   destination hash object
     * @param source source hash object
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_copy_state(@Out PointerByReference dest, @In Pointer source);

    /**
     * Writes the output length of the hash function to the given reference.
     *
     * @param hash   hash object
     * @param length output buffer to hold the hash function output length
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_output_length(@In Pointer hash, @Out NativeLongByReference length);

    /**
     * Writes the block size of the hash function to the given reference.
     *
     * @param hash hash object
     * @param size output buffer to hold the hash function output length
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_block_size(@In Pointer hash, @Out NativeLongByReference size);

    /**
     * Sends more input to the hash function.
     *
     * @param hash   hash object
     * @param input  input buffer
     * @param length number of bytes to read from the input buffer
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_update(@In Pointer hash, @In byte[] input, @In long length);

    /**
     * Finalizes the hash computation and writes the output to
     * out[0:botan_hash_output_length()] then reinitializes for computing
     * another digest as if botan_hash_clear had been called.
     *
     * @param hash hash object
     * @param out  output buffer
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_final(@In Pointer hash, @Out byte[] out);

    /**
     * Reinitializes the state of the hash computation. A hash can
     * be computed (with update/final) immediately.
     *
     * @param hash hash object
     * @return 0 on success, a negative value on failure
     */
    int botan_hash_clear(@In Pointer hash);

    /**
     * Frees all resources of the hash object.
     *
     * @param hash hash object
     * @return 0 if success, error if invalid object handle
     */
    //TODO: do we really need this ?
    int botan_hash_destroy(@In Pointer hash);

    /**
     * Initializes a message authentication code object.
     *
     * @param mac   MAC object
     * @param name  name of the hash function, e.g., "HMAC(SHA-384)"
     * @param flags should be 0 in current API revision, all other uses are reserved
     *              and return a negative value (error code)
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_init(@Out PointerByReference mac, @In String name, @In long flags);

    /**
     * Writes the output length of the message authentication code to the given reference.
     *
     * @param mac    MAC object
     * @param length output buffer to hold the MAC output length
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_output_length(@In Pointer mac, @Out NativeLongByReference length);

    /**
     * Sets the key on the MAC.
     *
     * @param mac    MAC object
     * @param key    buffer holding the key
     * @param length size of the key buffer in bytes
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_set_key(@In Pointer mac, @In byte[] key, @In long length);

    /**
     * Sends more input to the message authentication code.
     *
     * @param mac    MAC object
     * @param buffer input buffer
     * @param length number of bytes to read from the input buffer
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_update(@In Pointer mac, @In byte[] buffer, @In long length);

    /**
     * Finalizes the MAC computation and writes the output to
     * out[0:botan_mac_output_length()] then reinitializes for computing
     * another MAC as if botan_mac_clear had been called.
     *
     * @param mac MAC object
     * @param out output buffer
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_final(@In Pointer mac, @Out byte[] out);

    /**
     * Reinitializes the state of the MAC computation. A MAC can
     * be computed (with update/final) immediately.
     *
     * @param mac MAC object
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_clear(@In Pointer mac);

    /**
     * Frees all resources of the MAC object.
     *
     * @param mac MAC object
     * @return 0 if success, error if invalid object handle
     */
    //TODO: do we really need this ?
    int botan_mac_destroy(@In Pointer mac);

    /**
     * Gets the key length limits of this auth code
     *
     * @param mac              MAC object
     * @param minimumKeyLength if non-NULL, will be set to minimum keylength of MAC
     * @param maximumKeyLength if non-NULL, will be set to maximum keylength of MAC
     * @param keyLengthModulo  if non-NULL will be set to byte multiple of valid keys
     */
    int botan_mac_get_keyspec(@In Pointer mac, @Out NativeLongByReference minimumKeyLength,
                              @Out NativeLongByReference maximumKeyLength,
                              @Out NativeLongByReference keyLengthModulo);

    /**
     * Initializes a cipher object.
     *
     * @param cipher cipher object
     * @param name   name of the cipher including operating mode and padding
     * @param flags
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_init(@Out PointerByReference cipher, @In String name, @In long flags);

    /**
     * Returns the output length of this cipher, for a particular input length.
     *
     * @param cipher       cipher object
     * @param inputLength  input length
     * @param outputLength output length
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_output_length(@In Pointer cipher, @In long inputLength,
                                   @In @Out NativeLongByReference outputLength);

    /**
     * Returns if the specified nonce length is valid for this cipher.
     *
     * @param cipher      cipher object
     * @param nonceLength nonce length
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_valid_nonce_length(@In Pointer cipher, @In long nonceLength);

    /**
     * Gets the tag length of the cipher (0 for non-AEAD modes).
     *
     * @param cipher    cipher object
     * @param tagLength tag length
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_get_tag_length(@In Pointer cipher, @Out NativeLongByReference tagLength);

    /**
     * Gets the default nonce length of this cipher.
     *
     * @param cipher      cipher object
     * @param nonceLength nonce length
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_get_default_nonce_length(@In Pointer cipher, @Out NativeLongByReference nonceLength);

    /**
     * Returns the update granularity of the cipher; botan_cipher_update must be
     * called with blocks of this size, except for the final.
     *
     * @param cipher            cipher object
     * @param updateGranularity update granularity
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_get_update_granularity(@In Pointer cipher, @Out NativeLongByReference updateGranularity);

    /**
     * Gets information about the supported key lengths.
     *
     * @param cipher    cipher object
     * @param minKeylen minimal key length
     * @param maxKeylen maximal key length
     * @param modKeylen mod key length
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_get_keyspec(@In Pointer cipher, @Out NativeLongByReference minKeylen,
                                 @Out NativeLongByReference maxKeylen, @Out NativeLongByReference modKeylen);

    /**
     * Sets the key for this cipher object.
     *
     * @param cipher    cipher object
     * @param key       key
     * @param keyLength key length
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_set_key(@In Pointer cipher, @In byte[] key, @In long keyLength);

    /**
     * Resets the message specific state for this cipher. Without resetting the keys,
     * this resets the nonce, and any state associated with any message bits that have
     * been processed so far.
     * It is conceptually equivalent to calling botan_cipher_clear followed
     * by botan_cipher_set_key with the original key.
     *
     * @param cipher cipher object
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_reset(@In Pointer cipher);

    /**
     * Sets the associated data. Will fail if cipher is not an AEAD.
     *
     * @param cipher cipher object
     * @param ad     associated data
     * @param adLen  associated data length
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_set_associated_data(@In Pointer cipher, @In byte[] ad, @In long adLen);

    /**
     * Begin processing a new message using the provided nonce.
     *
     * @param cipher      cipher object
     * @param nonce       nonce data
     * @param nonceLength nonce data length
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_start(@In Pointer cipher, @In byte[] nonce, @In long nonceLength);

    /**
     * Encrypts some data.
     *
     * @param cipher        cipher object
     * @param flags
     * @param output        cipher output bytes
     * @param outputSize    cipher output size
     * @param outputWritten written output size
     * @param input         cipher input bytes
     * @param inputSize     cipher input size
     * @param inputConsumed cipher input consumed
     * @return 0 on success, a negative value on failure
     */
    int botan_cipher_update(@In Pointer cipher, @In long flags, @Out byte[] output,
                            @Out long outputSize,
                            @In @Out NativeLongByReference outputWritten,
                            @In byte[] input, @In long inputSize,
                            @In @Out NativeLongByReference inputConsumed);

    /**
     * Resets the key, nonce, AD and all other state on this cipher object.
     *
     * @param cipher cipher object
     * @return 0 if success, error if invalid object handle
     */
    int botan_cipher_clear(@In Pointer cipher);

    /**
     * Destroys the cipher object.
     *
     * @param cipher cipher object
     * @return 0 if success, error if invalid object handle
     */
    //TODO: do we really need this ?
    int botan_cipher_destroy(@In Pointer cipher);

}
