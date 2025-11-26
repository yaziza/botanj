/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.aead;

import static net.randombit.botan.Constants.BOTAN_DO_FINAL_FLAG;
import static net.randombit.botan.Constants.BOTAN_UPDATE_FLAG;
import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;
import static net.randombit.botan.jnr.BotanInstance.checkNativeCall;
import static net.randombit.botan.jnr.BotanInstance.singleton;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import net.randombit.botan.seckey.CipherMode;
import net.randombit.botan.seckey.block.BotanBlockCipher;

/**
 * Base class for AEAD (Authenticated Encryption with Associated Data) cipher implementations.
 */
public abstract class BotanAeadCipher extends BotanBlockCipher {

    /**
     * Holds the tag length for AEAD ciphers.
     */
    private int tLen = 128;

    /**
     * Whether this cipher has been properly initialized and can start
     * encrypting/decrypting.
     */
    private boolean isInitialized;

    private BotanAeadCipher(String name, CipherMode cipherMode, int blockSize) {
        super(name, cipherMode, blockSize);
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        final int tLenInBytes = tLen / Byte.SIZE;

        return Math.addExact(inputLen, tLenInBytes);
    }

    @Override
    protected boolean requiresDataBlockAligned() {
        return false;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        engineInit(opmode, key, random);

        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();

        } else if (params instanceof GCMParameterSpec) {
            iv = ((GCMParameterSpec) params).getIV();
            tLen = ((GCMParameterSpec) params).getTLen();

        } else {
            throw new InvalidAlgorithmParameterException("Error: Missing or invalid IvParameterSpec provided !");
        }

        checkNonceValid(iv.length);
        checkTagValid(tLen);
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        final byte[] inputFromOffset = Arrays.copyOfRange(src, offset, len);

        int err = singleton().botan_cipher_set_associated_data(cipherRef.getValue(), inputFromOffset, len);
        checkNativeCall(err, "botan_cipher_set_associated_data");

        startAeadMode();
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return doCipher(input, inputOffset, inputLen, BOTAN_DO_FINAL_FLAG);
    }

    @Override
    protected byte[] doCipher(byte[] input, int outputLength, int botanFlag) {
        if (!isInitialized) {
            startAeadMode();
        }

        return super.doCipher(input, outputLength, botanFlag);
    }

    @Override
    protected void engineReset() {
        super.engineReset();
        isInitialized = false;
    }

    private byte[] doCipher(byte[] input, int inputOffset, int inputLen, int botanFlag) {
        if ((inputLen == 0) && (BOTAN_UPDATE_FLAG == botanFlag)) {
            return EMPTY_BYTE_ARRAY;
        }

        input = (input == null) ? EMPTY_BYTE_ARRAY : input;

        final byte[] inputFromOffset = Arrays.copyOfRange(input, inputOffset, Math.addExact(inputOffset, inputLen));

        return doCipher(inputFromOffset, inputLen, botanFlag);
    }

    private void startAeadMode() {
        checkNonceValid(iv.length);

        final int err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
        checkNativeCall(err, "botan_cipher_start");

        isInitialized = true;
    }

    private void checkNonceValid(int nonceLength) {
        if (!isValidNonceLength(nonceLength)) {
            String msg = String.format("Nonce with length %d not allowed for algorithm %s", nonceLength, name);
            throw new IllegalArgumentException(msg);
        }
    }

    private void checkTagValid(int tagLength) {
        if (!isValidTagLength(tagLength)) {
            String msg = String.format("Tag length %d bits not allowed for algorithm %s", tagLength, name);
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

    /**
     * AES-GCM (Galois/Counter Mode) cipher implementation.
     */
    public static final class AesGcm extends BotanAeadCipher {

        /**
         * Constructs a new AES-GCM cipher.
         */
        public AesGcm() {
            super("AES", CipherMode.GCM, 16);
        }

        @Override
        protected String getBotanCipherName(int keySize) {
            return String.format("AES-%d/GCM", keySize * Byte.SIZE);
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength > 0;
        }

        @Override
        protected boolean isValidTagLength(int tagLength) {
            // GCM supports tag lengths: 96, 104, 112, 120, 128 bits
            // 128 is most common, 96 is minimum recommended
            return tagLength == 96 || tagLength == 104 || tagLength == 112
                || tagLength == 120 || tagLength == 128;
        }
    }

    /**
     * AES-CCM (Counter with CBC-MAC) cipher implementation.
     */
    public static final class AesCcm extends BotanAeadCipher {

        /**
         * Constructs a new AES-CCM cipher.
         */
        public AesCcm() {
            super("AES", CipherMode.CCM, 16);
        }

        @Override
        protected String getBotanCipherName(int keySize) {
            return String.format("AES-%d/CCM(16,4)", keySize * Byte.SIZE);
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength >= 0 && nonceLength <= 16;
        }

        @Override
        protected boolean isValidTagLength(int tagLength) {
            // CCM supports tag lengths: 32, 48, 64, 80, 96, 112, 128 bits
            // Must be even number of bytes (4-16 bytes)
            return tagLength >= 32 && tagLength <= 128 && tagLength % 16 == 0;
        }
    }

    /**
     * AES-SIV (Synthetic Initialization Vector) cipher implementation.
     */
    public static final class AesSiv extends BotanAeadCipher {

        /**
         * Constructs a new AES-SIV cipher.
         */
        public AesSiv() {
            super("AES", CipherMode.SIV, 16);
        }

        @Override
        protected String getBotanCipherName(int keySize) {
            return String.format("AES-%d/SIV", keySize * Byte.SIZE);
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
    }

    /**
     * AES-EAX cipher implementation.
     */
    public static final class AesEax extends BotanAeadCipher {

        /**
         * Constructs a new AES-EAX cipher.
         */
        public AesEax() {
            super("AES", CipherMode.EAX, 16);
        }

        @Override
        protected String getBotanCipherName(int keySize) {
            return String.format("AES-%d/EAX", keySize * Byte.SIZE);
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

    /**
     * AES-OCB (Offset Codebook Mode) cipher implementation.
     */
    public static final class AesOcb extends BotanAeadCipher {

        /**
         * Constructs a new AES-OCB cipher.
         */
        public AesOcb() {
            super("AES", CipherMode.OCB, 16);
        }

        @Override
        protected String getBotanCipherName(int keySize) {
            return String.format("AES-%d/OCB", keySize * Byte.SIZE);
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength != 0 && nonceLength < 16;
        }

        @Override
        protected boolean isValidTagLength(int tagLength) {
            // OCB supports tag lengths: 64, 96, 128 bits
            // 128 is most common
            return tagLength == 64 || tagLength == 96 || tagLength == 128;
        }
    }

}
