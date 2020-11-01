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
import static net.randombit.botan.util.BotanUtil.isNullOrEmpty;

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
        //TODO: check tag length valid
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        final byte[] inputFromOffset = Arrays.copyOfRange(src, offset, src.length);

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

    private byte[] doCipher(byte[] input, int inputOffset, int inputLen, int botanFlag) {
        if (isNullOrEmpty(input) || inputLen == 0) {
            return EMPTY_BYTE_ARRAY;
        }

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

    // AES-GCM
    public static final class AesGcm extends BotanAeadCipher {

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
    }

    // AES-CCM
    public static final class AesCcm extends BotanAeadCipher {

        public AesCcm() {
            super("AES", CipherMode.CCM, 16);
        }

        @Override
        protected String getBotanCipherName(int keySize) {
            return String.format("AES-%d/CCM(16)", keySize * Byte.SIZE);
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength >= 0 && nonceLength <= 16;
        }
    }

    // AES-SIV
    public static final class AesSiv extends BotanAeadCipher {

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
    }

    // AES-EAX
    public static final class AesEax extends BotanAeadCipher {

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
    }

    // AES-OCB
    public static final class AesOcb extends BotanAeadCipher {

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
    }

}
