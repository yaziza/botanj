/*
 * (C) 2025 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * A parameter specification for AEAD (Authenticated Encryption with Associated Data) cipher modes.
 *
 * <p>This class implements {@link AlgorithmParameterSpec} to provide a convenient way to specify
 * the nonce/IV and authentication tag size for AEAD ciphers.
 *
 * <p>This is particularly useful as an alternative to {@link javax.crypto.spec.GCMParameterSpec}
 * and provides compatibility across different JDK versions and AEAD cipher modes beyond GCM.
 *
 * <h2>Usage Example</h2>
 *
 * <pre>{@code
 * // Create parameter spec with tag size and nonce
 * byte[] nonce = new byte[12];
 * AeadParameterSpec spec = new AeadParameterSpec(128, nonce);
 *
 * // Using with cipher
 * Cipher cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding", "Botan");
 * cipher.init(Cipher.ENCRYPT_MODE, key, spec);
 * cipher.updateAAD(aad); // Optional: set AAD separately
 * byte[] ciphertext = cipher.doFinal(plaintext);
 * }</pre>
 *
 * @see AlgorithmParameterSpec
 * @see javax.crypto.spec.GCMParameterSpec
 * @since 0.1.0
 */
public class AeadParameterSpec implements AlgorithmParameterSpec {

  private final byte[] iv;
  private final int tLen;

  /**
   * Constructs a parameter specification for AEAD cipher modes with a tag length and nonce.
   *
   * <p>This constructor signature matches {@link javax.crypto.spec.GCMParameterSpec} for
   * compatibility.
   *
   * @param tLen the authentication tag length in bits. The supported tag lengths depend on the
   *     cipher algorithm (e.g., 128 bits for ChaCha20-Poly1305).
   * @param iv the buffer containing the nonce (initialization vector). The required length depends
   *     on the cipher algorithm (e.g., 12 bytes for ChaCha20-Poly1305, 24 bytes for
   *     XChaCha20-Poly1305).
   * @throws IllegalArgumentException if {@code src} is null, or if {@code tLen} is negative or not
   *     a multiple of 8
   */
  public AeadParameterSpec(int tLen, byte[] iv) {
    this(tLen, iv, 0, iv == null ? 0 : iv.length);
  }

  /**
   * Constructs a parameter specification for AEAD cipher modes using a subset of a buffer as the
   * nonce.
   *
   * <p>This constructor signature matches {@link javax.crypto.spec.GCMParameterSpec} for
   * compatibility.
   *
   * @param tLen the authentication tag length in bits. The supported tag lengths depend on the
   *     cipher algorithm (e.g., 128 bits for ChaCha20-Poly1305).
   * @param iv the buffer containing the nonce (initialization vector).
   * @param offset the offset in {@code iv} where the nonce data starts
   * @param len the number of nonce bytes. The required length depends on the cipher algorithm
   *     (e.g., 12 bytes for ChaCha20-Poly1305, 24 bytes for XChaCha20-Poly1305).
   * @throws IllegalArgumentException if {@code iv} is null, or if {@code tLen} is negative or not a
   *     multiple of 8, or if {@code offset} and {@code len} specify a range that exceeds the bounds
   *     of {@code iv}
   * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code len} is negative
   */
  public AeadParameterSpec(int tLen, byte[] iv, int offset, int len) {
    if (tLen < 0) {
      throw new IllegalArgumentException("Tag length cannot be negative");
    }

    if (tLen % Byte.SIZE != 0) {
      throw new IllegalArgumentException("Tag length must be a multiple of 8 bits");
    }

    if (iv == null) {
      throw new IllegalArgumentException("IV missing");
    }
    if (offset < 0) {
      throw new ArrayIndexOutOfBoundsException("offset is negative");
    }
    if (len < 0) {
      throw new ArrayIndexOutOfBoundsException("len is negative");
    }
    if (iv.length - offset < len) {
      throw new IllegalArgumentException("IV buffer too short for given offset/length combination");
    }

    this.tLen = tLen;
    this.iv = Arrays.copyOfRange(iv, offset, offset + len);
  }

  /**
   * Returns the initialization vector (nonce).
   *
   * @return a copy of the IV
   */
  public byte[] getIV() {
    return iv.clone();
  }

  /**
   * Returns the authentication tag length in bits.
   *
   * @return the tag length in bits
   */
  public int getTLen() {
    return tLen;
  }

  /**
   * Compares this AeadParameterSpec to the specified object.
   *
   * @param obj the object to compare with
   * @return true if the objects are equal, false otherwise
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof AeadParameterSpec other)) {
      return false;
    }

    return this.tLen == other.tLen && Arrays.equals(this.iv, other.iv);
  }

  /**
   * Returns a hash code for this AeadParameterSpec.
   *
   * @return a hash code value
   */
  @Override
  public int hashCode() {
    int result = tLen;
    result = 31 * result + Arrays.hashCode(iv);
    return result;
  }

  /**
   * Returns a string representation of this AeadParameterSpec.
   *
   * @return a string representation
   */
  @Override
  public String toString() {
    return "AeadParameterSpec{" + "nonceLength=" + iv.length + ", tLen=" + tLen + '}';
  }
}
