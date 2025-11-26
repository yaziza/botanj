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

/**
 * JNR-FFI interface defining native function bindings to the Botan cryptography library.
 *
 * <p>This interface provides direct access to Botan's C FFI (Foreign Function Interface) through JNR-FFI.
 * It defines Java method signatures that map to native Botan functions, handling type conversions and
 * memory management for cross-language calls.</p>
 *
 * <h2>Purpose and Architecture</h2>
 *
 * <p>BotanLibrary serves as the low-level binding layer between Java and native Botan code:
 * <ul>
 *   <li><b>Interface, not Implementation:</b> This is a JNR-FFI interface - JNR automatically generates
 *       the implementation by binding to the native library at runtime</li>
 *   <li><b>Direct Native Access:</b> All methods directly correspond to Botan C FFI functions</li>
 *   <li><b>Memory Safety:</b> Uses JNR-FFI annotations (@In, @Out) to manage native memory safely</li>
 *   <li><b>Singleton Access:</b> Instances are created and managed by {@link BotanInstance}</li>
 * </ul>
 *
 * <h2>Function Categories</h2>
 *
 * <p>The library provides bindings for the following Botan operations:</p>
 *
 * <h3>Utility Functions</h3>
 * <ul>
 *   <li>{@link #botan_version_string()} - Get Botan library version</li>
 *   <li>{@link #botan_ffi_supports_api(long)} - Check FFI API version support</li>
 *   <li>{@link #botan_error_description(int)} - Convert error codes to descriptions</li>
 * </ul>
 *
 * <h3>Encoding Functions</h3>
 * <ul>
 *   <li>{@link #botan_hex_encode(byte[], long, byte[], long)} - Binary to hexadecimal</li>
 *   <li>{@link #botan_hex_decode(byte[], long, byte[], NativeLongByReference)} - Hexadecimal to binary</li>
 *   <li>{@link #botan_base64_encode(byte[], long, byte[], NativeLongByReference)} - Binary to Base64</li>
 *   <li>{@link #botan_base64_decode(String, long, byte[], NativeLongByReference)} - Base64 to binary</li>
 * </ul>
 *
 * <h3>Hash Functions (Message Digests)</h3>
 * <ul>
 *   <li>{@link #botan_hash_init(PointerByReference, String, long)} - Initialize hash object</li>
 *   <li>{@link #botan_hash_update(Pointer, byte[], long)} - Add data to hash</li>
 *   <li>{@link #botan_hash_final(Pointer, byte[])} - Finalize and get digest</li>
 *   <li>{@link #botan_hash_copy_state(PointerByReference, Pointer)} - Clone hash state</li>
 *   <li>{@link #botan_hash_clear(Pointer)} - Reset hash state</li>
 *   <li>{@link #botan_hash_destroy(Pointer)} - Free hash object</li>
 * </ul>
 *
 * <h3>Message Authentication Codes (MACs)</h3>
 * <ul>
 *   <li>{@link #botan_mac_init(PointerByReference, String, long)} - Initialize MAC object</li>
 *   <li>{@link #botan_mac_set_key(Pointer, byte[], long)} - Set MAC key</li>
 *   <li>{@link #botan_mac_update(Pointer, byte[], long)} - Add data to MAC</li>
 *   <li>{@link #botan_mac_final(Pointer, byte[])} - Finalize and get MAC tag</li>
 *   <li>{@link #botan_mac_clear(Pointer)} - Reset MAC state</li>
 *   <li>{@link #botan_mac_destroy(Pointer)} - Free MAC object</li>
 * </ul>
 *
 * <h3>Symmetric Ciphers</h3>
 * <ul>
 *   <li>{@link #botan_cipher_init(PointerByReference, String, long)} - Initialize cipher object</li>
 *   <li>{@link #botan_cipher_set_key(Pointer, byte[], long)} - Set cipher key</li>
 *   <li>{@link #botan_cipher_start(Pointer, byte[], long)} - Start cipher with IV/nonce</li>
 *   <li>{@link #botan_cipher_update(Pointer, long, byte[], long, NativeLongByReference, byte[], long, NativeLongByReference)}
 *       - Process data (encrypt/decrypt)</li>
 *   <li>{@link #botan_cipher_reset(Pointer)} - Reset cipher state</li>
 *   <li>{@link #botan_cipher_destroy(Pointer)} - Free cipher object</li>
 * </ul>
 *
 * <h2>Error Handling</h2>
 *
 * <p>All native functions return an integer error code:
 * <ul>
 *   <li><b>0</b> indicates success</li>
 *   <li><b>Negative values</b> indicate errors (e.g., -1 for invalid input, -20 for bad MAC)</li>
 *   <li>Use {@link #botan_error_description(int)} to convert error codes to human-readable messages</li>
 *   <li>{@link BotanInstance#checkNativeCall(int, String)} provides centralized error checking</li>
 * </ul>
 *
 * <h2>Memory Management</h2>
 *
 * <p>Proper resource cleanup is critical when working with native objects:
 * <ul>
 *   <li><b>Initialization functions</b> (e.g., botan_hash_init) allocate native memory</li>
 *   <li><b>Destroy functions</b> (e.g., botan_hash_destroy) must be called to free memory</li>
 *   <li><b>Java wrappers</b> use Cleaner API to ensure automatic cleanup on garbage collection</li>
 *   <li><b>PointerByReference</b> is used for output parameters that receive native object handles</li>
 * </ul>
 *
 * <h2>Usage Pattern</h2>
 *
 * <p>Direct usage of this interface is not recommended. Instead, use the high-level JCA wrapper classes:</p>
 *
 * <pre>{@code
 * // DON'T use BotanLibrary directly:
 * BotanLibrary lib = BotanInstance.singleton();
 * PointerByReference hashRef = new PointerByReference();
 * lib.botan_hash_init(hashRef, "SHA-256", 0);
 * // ... manual memory management required ...
 * lib.botan_hash_destroy(hashRef.getValue());
 *
 * // DO use JCA wrappers instead:
 * MessageDigest sha256 = MessageDigest.getInstance("SHA-256", "Botan");
 * byte[] hash = sha256.digest(data);
 * // Automatic resource management via Cleaner
 * }</pre>
 *
 * <h2>JNR-FFI Annotations</h2>
 *
 * <p>This interface uses JNR-FFI annotations to control parameter marshalling:
 * <ul>
 *   <li><b>@In</b> - Input parameter (Java to native)</li>
 *   <li><b>@Out</b> - Output parameter (native to Java)</li>
 *   <li><b>PointerByReference</b> - Reference to a native pointer (for object handles)</li>
 *   <li><b>NativeLongByReference</b> - Reference to a native long (for output sizes)</li>
 *   <li><b>Pointer</b> - Opaque native pointer (for object handles)</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 *
 * <p>The native Botan library functions are NOT thread-safe for individual objects:
 * <ul>
 *   <li>Each native object (hash, MAC, cipher) must be accessed by only one thread</li>
 *   <li>Different threads can use different native objects concurrently</li>
 *   <li>Java wrapper classes inherit this thread-safety model</li>
 * </ul>
 *
 * <h2>Native Library Requirements</h2>
 *
 * <p>This interface requires the Botan 3.x native library:
 * <ul>
 *   <li><b>Library name:</b> "botan-3"</li>
 *   <li><b>Minimum version:</b> Botan 3.0.0</li>
 *   <li><b>FFI API:</b> Uses Botan's C FFI (stable ABI)</li>
 *   <li><b>Platform support:</b> Linux, macOS, Windows</li>
 * </ul>
 *
 * <h2>Implementation Notes</h2>
 *
 * <ul>
 *   <li><b>Auto-generated Implementation:</b> JNR-FFI generates the implementation at runtime by analyzing
 *       this interface and creating native bindings</li>
 *   <li><b>No Manual JNI:</b> No need for hand-written JNI code - JNR handles everything</li>
 *   <li><b>Type Mapping:</b> JNR automatically maps Java types to C types (int→int, byte[]→uint8_t*, etc.)</li>
 *   <li><b>Performance:</b> Near-native performance due to efficient JNR code generation</li>
 * </ul>
 *
 * @see BotanInstance
 * @see jnr.ffi.LibraryLoader
 * @author Yasser Aziza
 * @since 0.1.0
 */
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
    int botan_mac_destroy(@In Pointer mac);

    /**
     * Gets the key length limits of this auth code
     *
     * @param mac              MAC object
     * @param minimumKeyLength if non-NULL, will be set to minimum keylength of MAC
     * @param maximumKeyLength if non-NULL, will be set to maximum keylength of MAC
     * @param keyLengthModulo  if non-NULL will be set to byte multiple of valid keys
     * @return 0 on success, a negative value on failure
     */
    int botan_mac_get_keyspec(@In Pointer mac, @Out NativeLongByReference minimumKeyLength,
                              @Out NativeLongByReference maximumKeyLength,
                              @Out NativeLongByReference keyLengthModulo);

    /**
     * Initializes a cipher object.
     *
     * @param cipher cipher object
     * @param name   name of the cipher including operating mode and padding
     * @param flags  initialization flags (typically 0)
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
     * @param flags         operation flags (0 for update, 1 for final)
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
    int botan_cipher_destroy(@In Pointer cipher);

}
