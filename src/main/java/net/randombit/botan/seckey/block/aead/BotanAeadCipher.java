/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.block.aead;

import static net.randombit.botan.Constants.BOTAN_DO_FINAL_FLAG;
import static net.randombit.botan.Constants.BOTAN_ENCRYPT_MODE;
import static net.randombit.botan.Constants.BOTAN_UPDATE_FLAG;
import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;
import static net.randombit.botan.jnr.BotanInstance.checkNativeCall;
import static net.randombit.botan.jnr.BotanInstance.singleton;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import net.randombit.botan.seckey.CipherMode;
import net.randombit.botan.seckey.block.BotanBlockCipher;
import net.randombit.botan.spec.AeadParameterSpec;

/** Base class for AEAD (Authenticated Encryption with Associated Data) cipher implementations. */
public abstract class BotanAeadCipher extends BotanBlockCipher {

  /**
   * Native botan_cipher_set_associated_data() will be called only once. The engineUpdateAAD input
   * will be buffered.
   */
  protected byte[] aad_buffer = EMPTY_BYTE_ARRAY;

  /** Whether this cipher has been properly initialized and can start encrypting/decrypting. */
  protected boolean isInitialized;

  /** Holds the tag length for AEAD ciphers. */
  protected int tLen = 128;

  private BotanAeadCipher(String name, CipherMode cipherMode, int blockSize) {
    super(name, cipherMode, blockSize);
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    if (tLen % Byte.SIZE != 0) {
      throw new ArithmeticException("Tag length is not a multiple of byte size");
    }
    final int tLenInBytes = tLen / Byte.SIZE;

    return Math.addExact(inputLen, tLenInBytes);
  }

  @Override
  protected boolean requiresDataBlockAligned() {
    return false;
  }

  @Override
  protected java.security.AlgorithmParameters engineGetParameters() {
    java.security.AlgorithmParameters parameters = null;

    if (iv != null && iv.length > 0) {
      try {
        parameters = java.security.AlgorithmParameters.getInstance(name);
        parameters.init(new AeadParameterSpec(tLen, iv));

      } catch (java.security.NoSuchAlgorithmException
          | java.security.spec.InvalidParameterSpecException e) {
        parameters = null;
      }
    }

    return parameters;
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {

    if (params instanceof AeadParameterSpec aeadParameterSpec) {
      iv = aeadParameterSpec.getIV();
      tLen = aeadParameterSpec.getTLen();

    } else if (params instanceof GCMParameterSpec gcmParameterSpec) {
      iv = gcmParameterSpec.getIV();
      tLen = gcmParameterSpec.getTLen();

    } else if (params instanceof IvParameterSpec ivParameterSpec) {
      iv = ivParameterSpec.getIV();

    } else {
      throw new InvalidAlgorithmParameterException(
          "Error: Missing or invalid parameter spec provided!");
    }

    checkNonceValid(iv.length);
    checkTagValid(tLen);

    if (isInitialized) {
      int err = singleton().botan_cipher_reset(cipherRef.getValue());
      checkNativeCall(err, "botan_cipher_reset");

      payload_buffer = EMPTY_BYTE_ARRAY;
      aad_buffer = EMPTY_BYTE_ARRAY;
      isInitialized = false;
    }

    engineInit(opmode, key, random);
  }

  @Override
  protected void engineUpdateAAD(byte[] src, int offset, int len) {

    // resize buffer and append the new input
    final byte[] currentInput = Arrays.copyOf(aad_buffer, Math.addExact(len, aad_buffer.length));
    System.arraycopy(src, offset, currentInput, aad_buffer.length, len);

    aad_buffer = currentInput;
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
    return doCipher(input, inputOffset, inputLen, BOTAN_DO_FINAL_FLAG);
  }

  @Override
  protected byte[] doCipher(byte[] input, int outputLength, int botanFlag) {
    if (!isInitialized) {
      int err =
          singleton()
              .botan_cipher_set_associated_data(
                  cipherRef.getValue(), aad_buffer, aad_buffer.length);
      checkNativeCall(err, "botan_cipher_set_associated_data");

      startAeadMode();
    }

    return super.doCipher(input, outputLength, botanFlag);
  }

  @Override
  protected void engineReset() {
    int err = singleton().botan_cipher_reset(cipherRef.getValue());
    checkNativeCall(err, "botan_cipher_reset");

    if (mode == BOTAN_ENCRYPT_MODE) {
      this.iv = null;
    }

    payload_buffer = EMPTY_BYTE_ARRAY;
    aad_buffer = EMPTY_BYTE_ARRAY;

    isInitialized = false;
  }

  private byte[] doCipher(byte[] input, int inputOffset, int inputLen, int botanFlag) {
    if ((inputLen == 0) && (BOTAN_UPDATE_FLAG == botanFlag)) {
      return EMPTY_BYTE_ARRAY;
    }

    input = (input == null) ? EMPTY_BYTE_ARRAY : input;

    final byte[] inputFromOffset =
        Arrays.copyOfRange(input, inputOffset, Math.addExact(inputOffset, inputLen));

    return doCipher(inputFromOffset, inputLen, botanFlag);
  }

  private void startAeadMode() {
    if (iv == null && mode == BOTAN_ENCRYPT_MODE) {
      throw new IllegalStateException("Missing or invalid IvParameterSpec provided!");
    }
    final int err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
    checkNativeCall(err, "botan_cipher_start");

    isInitialized = true;
  }

  private void checkNonceValid(int nonceLength) {
    if (!isValidNonceLength(nonceLength)) {
      String msg =
          String.format("Nonce with length %d not allowed for algorithm %s", nonceLength, name);
      throw new IllegalArgumentException(msg);
    }
  }

  private void checkTagValid(int tagLength) {
    if (!isValidTagLength(tagLength)) {
      String msg =
          String.format("Tag length %d bits not allowed for algorithm %s", tagLength, name);
      throw new IllegalArgumentException(msg);
    }
  }

  /**
   * Checks whether the given tag length is supported.
   *
   * @param tagLength the tag length in bits
   * @return {@code true} if the given tag length is supported, {@code false} otherwise.
   */
  protected abstract boolean isValidTagLength(int tagLength);

  /** AES-GCM (Galois/Counter Mode) cipher implementation. */
  public static final class AesGcm extends BotanAeadCipher {

    /** Constructs a new AES-GCM cipher. */
    public AesGcm() {
      super("AES", CipherMode.GCM, 16);
    }

    @Override
    protected String getBotanCipherName(int keySize) {
      return String.format("AES-%d/GCM", Math.multiplyExact(keySize, Byte.SIZE));
    }

    @Override
    protected boolean isValidNonceLength(int nonceLength) {
      return nonceLength > 0;
    }

    @Override
    protected boolean isValidTagLength(int tagLength) {
      // GCM supports tag lengths: 96, 104, 112, 120, 128 bits
      // 128 is most common, 96 is minimum recommended
      return tagLength == 96
          || tagLength == 104
          || tagLength == 112
          || tagLength == 120
          || tagLength == 128;
    }
  }

  /** AES-CCM (Counter with CBC-MAC) cipher implementation. */
  public static final class AesCcm extends BotanAeadCipher {

    /** Constructs a new AES-CCM cipher. */
    public AesCcm() {
      super("AES", CipherMode.CCM, 16);
    }

    @Override
    protected String getBotanCipherName(int keySize) {
      // Calculate T (tag length in bytes) from tLen (tag length in bits)
      int tagLengthBytes = tLen / Byte.SIZE;

      // Calculate L value from nonce length
      // In CCM: nonce_length = 15 - L, so L = 15 - nonce_length
      // Use default L=4 (11-byte nonce) if IV not yet set
      int lValue = (iv != null && iv.length > 0) ? (15 - iv.length) : 4;

      return String.format(
          "AES-%d/CCM(%d,%d)", Math.multiplyExact(keySize, Byte.SIZE), tagLengthBytes, lValue);
    }

    @Override
    protected boolean isValidNonceLength(int nonceLength) {
      // CCM nonce length must be between 7 and 13 bytes
      // This corresponds to L values between 2 and 8 (L = 15 - nonceLength)
      return nonceLength >= 7 && nonceLength <= 13;
    }

    @Override
    protected boolean isValidTagLength(int tagLength) {
      // CCM supports tag lengths: 32, 48, 64, 80, 96, 112, 128 bits
      // Must be even number of bytes (4-16 bytes)
      return tagLength >= 32 && tagLength <= 128 && tagLength % 16 == 0;
    }
  }

  /** AES-SIV (Synthetic Initialization Vector) cipher implementation. */
  public static final class AesSiv extends BotanAeadCipher {

    /** Constructs a new AES-SIV cipher. */
    public AesSiv() {
      super("AES", CipherMode.SIV, 16);
    }

    @Override
    protected String getBotanCipherName(int keySize) {
      return String.format("AES-%d/SIV", Math.multiplyExact(keySize, Byte.SIZE) / 2);
    }

    @Override
    protected boolean isValidNonceLength(int nonceLength) {
      // SIV supports arbitrary nonce lengths
      return true;
    }

    @Override
    protected boolean isValidTagLength(int tagLength) {
      // SIV always uses 128-bit tag (fixed)
      return tagLength == 128;
    }

    @Override
    protected void engineReset() {
      int err = singleton().botan_cipher_reset(cipherRef.getValue());
      checkNativeCall(err, "botan_cipher_reset");

      err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
      checkNativeCall(err, "botan_cipher_start");

      aad_buffer = EMPTY_BYTE_ARRAY;
      payload_buffer = EMPTY_BYTE_ARRAY;

      this.isInitialized = true;
    }
  }

  /** AES-EAX cipher implementation. */
  public static final class AesEax extends BotanAeadCipher {

    /** Constructs a new AES-EAX cipher. */
    public AesEax() {
      super("AES", CipherMode.EAX, 16);
    }

    @Override
    protected String getBotanCipherName(int keySize) {
      return String.format("AES-%d/EAX", Math.multiplyExact(keySize, Byte.SIZE));
    }

    @Override
    protected boolean isValidNonceLength(int nonceLength) {
      // EAX supports arbitrary nonce lengths
      return true;
    }

    @Override
    protected boolean isValidTagLength(int tagLength) {
      // EAX supports any tag length that's a multiple of 8 bits
      // Typically 128 bits, but can be any size
      return tagLength > 0 && tagLength % 8 == 0 && tagLength <= 128;
    }
  }

  /** AES-OCB (Offset Codebook Mode) cipher implementation. */
  public static final class AesOcb extends BotanAeadCipher {

    /** Constructs a new AES-OCB cipher. */
    public AesOcb() {
      super("AES", CipherMode.OCB, 16);
    }

    @Override
    protected String getBotanCipherName(int keySize) {
      return String.format("AES-%d/OCB", Math.multiplyExact(keySize, Byte.SIZE));
    }

    @Override
    protected boolean isValidNonceLength(int nonceLength) {
      if (nonceLength == 0) {
        return false;
      }
      if (engineGetBlockSize() == 16) {
        return nonceLength < 16;
      } else {
        return nonceLength < (engineGetBlockSize() - 1);
      }
    }

    @Override
    protected boolean isValidTagLength(int tagLength) {
      // OCB supports tag lengths: 64, 96, 128 bits
      // 128 is most common
      return tagLength == 64 || tagLength == 96 || tagLength == 128;
    }
  }

  /** ChaCha20-Poly1305 AEAD cipher implementation. */
  public static final class ChaCha20Poly1305 extends BotanAeadCipher {

    /** Constructs a new ChaCha20-Poly1305 cipher. */
    public ChaCha20Poly1305() {
      super("ChaCha20", CipherMode.Poly1305, 64);
    }

    @Override
    protected String getBotanCipherName(int keySize) {
      return "ChaCha20Poly1305";
    }

    @Override
    protected boolean isValidNonceLength(int nonceLength) {
      return nonceLength == 8 || nonceLength == 12;
    }

    @Override
    protected boolean isValidTagLength(int tagLength) {
      // ChaCha20-Poly1305 uses fixed 128-bit tag
      return tagLength == 128;
    }
  }

  /** XChaCha20-Poly1305 AEAD cipher implementation. */
  public static final class XChaCha20Poly1305 extends BotanAeadCipher {

    /** Constructs a new XChaCha20-Poly1305 cipher. */
    public XChaCha20Poly1305() {
      super("XChaCha20", CipherMode.Poly1305, 64);
    }

    @Override
    protected String getBotanCipherName(int keySize) {
      // Botan uses the same cipher name "ChaCha20Poly1305" for XChaCha20-Poly1305
      // The XChaCha20 variant is automatically selected when a 192-bit (24-byte) nonce is used
      return "ChaCha20Poly1305";
    }

    @Override
    protected boolean isValidNonceLength(int nonceLength) {
      // XChaCha20-Poly1305 uses 192-bit (24-byte) extended nonce
      return nonceLength == 24;
    }

    @Override
    protected boolean isValidTagLength(int tagLength) {
      // XChaCha20-Poly1305 uses fixed 128-bit tag
      return tagLength == 128;
    }
  }
}
