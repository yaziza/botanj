/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.block;

import static net.randombit.botan.Constants.BOTAN_DO_FINAL_FLAG;
import static net.randombit.botan.Constants.BOTAN_UPDATE_FLAG;
import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;
import static net.randombit.botan.jnr.BotanInstance.checkNativeCall;
import static net.randombit.botan.jnr.BotanInstance.singleton;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import jnr.ffi.byref.NativeLongByReference;
import net.randombit.botan.seckey.BotanBaseAsymmetricCipher;
import net.randombit.botan.seckey.CipherMode;
import net.randombit.botan.util.PaddingAlgorithm;

public abstract class BotanBlockCipher extends BotanBaseAsymmetricCipher {

    /**
     * Holds the {@link CipherMode}.
     */
    protected final CipherMode cipherMode;

    /**
     * Holds the block size of the cipher in bytes.
     */
    private final int blockSize;

    /**
     * Holds the padding algorithm (e.g. PKCS5)
     */
    protected PaddingAlgorithm padding = PaddingAlgorithm.NO_PADDING;

    /**
     * Botan update granularity for this cipher. botan_cipher_update() must be
     * called with blocks of this size, except for doFinal().
     */
    protected int updateGranularity;

    /**
     * Native botan_cipher_update() will be called only with blocks of
     * size {@link BotanBlockCipher#updateGranularity}. The rest will be held
     * until the next update or doFinal call.
     */
    protected byte[] buffer;

    protected BotanBlockCipher(String name, CipherMode cipherMode, int blockSize) {
        super(name);

        this.cipherMode = Objects.requireNonNull(cipherMode);
        this.blockSize = blockSize;
    }

    /**
     * Whether the operation modes requires data block aligned or not.
     *
     * @return {@code true} if data must be block size aligned, {@code false} otherwise.
     */
    protected abstract boolean requiresDataBlockAligned();

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        this.padding = PaddingAlgorithm.fromName(padding);
        if (!cipherMode.isPaddingSupported(this.padding)) {
            throw new NoSuchPaddingException("Padding algorithm " + padding + " not allowed for mode " + cipherMode);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return blockSize;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (isWithoutPadding() || isDecrypting(mode)) {
            return inputLen;
        }

        final int result = Math.addExact(inputLen, blockSize);
        return Math.subtractExact(result, (inputLen % blockSize));
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        super.engineInit(opmode, key, random);

        final NativeLongByReference updateGranularity = new NativeLongByReference();

        final int err = singleton().botan_cipher_get_update_granularity(cipherRef.getValue(), updateGranularity);
        checkNativeCall(err, "botan_cipher_get_update_granularity");

        this.updateGranularity = updateGranularity.intValue();
        this.buffer = EMPTY_BYTE_ARRAY;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (inputLen == 0) {
            return EMPTY_BYTE_ARRAY;
        }

        // resize buffer and append the new input
        final byte[] currentInput = Arrays.copyOf(buffer, Math.addExact(inputLen, buffer.length));
        System.arraycopy(input, inputOffset, currentInput, buffer.length, inputLen);

        // compute the new buffer offset
        final int bufferOffset = currentInput.length % updateGranularity;

        final int index = Math.subtractExact(currentInput.length, bufferOffset);
        final byte[] doCipherInput = Arrays.copyOfRange(currentInput, 0, index);
        buffer = Arrays.copyOfRange(currentInput, index, currentInput.length);

        return (doCipherInput.length == 0) ? EMPTY_BYTE_ARRAY
                : doCipher(doCipherInput, 0, doCipherInput.length, BOTAN_UPDATE_FLAG);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException {
        boolean isBlockSizeAligned = Math.addExact(inputLen, buffer.length) % blockSize == 0;
        if (isWithoutPadding() && requiresDataBlockAligned() && !isBlockSizeAligned) {
            throw new IllegalBlockSizeException("Data not block size aligned");
        }

        return doCipher(input, inputOffset, inputLen, BOTAN_DO_FINAL_FLAG);
    }

    @Override
    protected void engineReset() {
        super.engineReset();
        buffer = EMPTY_BYTE_ARRAY;
    }

    private byte[] doCipher(byte[] input, int inputOffset, int inputLen, int botanFlag) {
        boolean isEmptyInput = (inputLen == 0) && (buffer.length == 0);

        if (isEmptyInput && Cipher.DECRYPT_MODE == mode) {
            return EMPTY_BYTE_ARRAY;
        }

        if (isEmptyInput && Cipher.ENCRYPT_MODE == mode) {
            // Encrypt last padding block
            input = new byte[blockSize];
            inputLen = blockSize;
        }

        final byte[] inputFromOffset = addBufferedInput(input, inputOffset, inputLen);

        return super.doCipher(inputFromOffset, inputFromOffset.length, botanFlag);
    }

    private byte[] addBufferedInput(byte[] input, int inputOffset, int inputLen) {
        // resize buffer
        final int index = Math.addExact(inputLen, buffer.length);
        final byte[] result = Arrays.copyOf(buffer, index);

        if (inputLen > 0) {
            // append the new input
            byte[] inputFromOffset = Arrays.copyOfRange(input, inputOffset, input.length);
            System.arraycopy(inputFromOffset, 0, result, buffer.length, index);
        }

        return result;
    }

    private boolean isWithoutPadding() {
        return PaddingAlgorithm.NO_PADDING == padding;
    }

    @Override
    protected boolean isValidNonceLength(int nonceLength) {
        return true;
    }

    // AES
    public static final class AesCbc extends BotanBlockCipher {

        public AesCbc() {
            super("AES", CipherMode.CBC, 16);
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return String.format("AES-%d/CBC/%s", keyLength * Byte.SIZE, padding.getName());
        }

        @Override
        protected boolean requiresDataBlockAligned() {
            return true;
        }

    }

    public static final class AesCfb extends BotanBlockCipher {

        public AesCfb() {
            super("AES", CipherMode.CFB, 16);
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return String.format("AES-%d/CFB", keyLength * Byte.SIZE);
        }

        @Override
        protected boolean requiresDataBlockAligned() {
            return false;
        }
    }

    // DES
    public static final class DesCbc extends BotanBlockCipher {
        public DesCbc() {
            super("DES", CipherMode.CBC, 8);
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return "DES/CBC/" + padding.getName();
        }

        @Override
        protected boolean requiresDataBlockAligned() {
            return true;
        }
    }

    public static final class DesCfb extends BotanBlockCipher {
        public DesCfb() {
            super("DES", CipherMode.CFB, 8);
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return "DES/CFB";
        }

        @Override
        protected boolean requiresDataBlockAligned() {
            return false;
        }
    }

    // 3DES
    public static final class DesEdeCbc extends BotanBlockCipher {
        public DesEdeCbc() {
            super("DESede", CipherMode.CBC, 8);
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return "3DES/CBC/" + padding.getName();
        }

        @Override
        protected boolean requiresDataBlockAligned() {
            return true;
        }
    }

    public static final class DesEdeCfb extends BotanBlockCipher {
        public DesEdeCfb() {
            super("DESede", CipherMode.CFB, 8);
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return "3DES/CFB";
        }

        @Override
        protected boolean requiresDataBlockAligned() {
            return false;
        }
    }

}
