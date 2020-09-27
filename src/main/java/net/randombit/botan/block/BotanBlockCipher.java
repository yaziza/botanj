/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.block;

import static net.randombit.botan.Botan.checkNativeCall;
import static net.randombit.botan.Botan.singleton;
import static net.randombit.botan.BotanUtil.checkKeySize;
import static net.randombit.botan.BotanUtil.checkSecretKey;
import static net.randombit.botan.Constants.BOTAN_DO_FINAL_FLAG;
import static net.randombit.botan.Constants.BOTAN_UPDATE_FLAG;
import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Objects;

import jnr.ffi.Pointer;
import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;
import net.randombit.botan.BotanUtil;

public abstract class BotanBlockCipher extends CipherSpi {

    private static final String ERR_MSG_GCM_WITHOUT_IV = "GCM does not support empty nonces!";
    private static final String ERR_MSG_INVALID_KEY_SIZE = "Invalid key size %d for algorithm %s";

    /**
     * Holds the name of the block cipher algorithm (e.g. 'AES').
     */
    private final String name;

    /**
     * Holds the {@link CipherMode}.
     */
    private final CipherMode cipherMode;

    /**
     * Holds the block size of the cipher in bytes.
     */
    private final int blockSize;

    /**
     * Holds the reference to the block cipher object referenced by botan.
     */
    private final PointerByReference cipherRef;

    /**
     * Holds the padding algorithm (e.g. PKCS5)
     */
    private PaddingAlgorithm padding;

    /**
     * Holds the cipher operation mode in native botan terms (0: Encryption, 1: Decryption)
     */
    private int mode;

    /**
     * Holds the Initial Vector (IV).
     */
    private byte[] iv;

    /**
     * Holds the tag length for AEAD ciphers.
     */
    private int tLen;

    /**
     * Whether this cipher has been properly initialized and can start
     * encrypting/decrypting.
     */
    private boolean canStart;

    /**
     * Botan update granularity for this cipher. botan_cipher_update() must be
     * called with blocks of this size, except for doFinal().
     */
    private int updateGranularity;

    /**
     * Native botan_cipher_update() will be called only with blocks of
     * size {@link BotanBlockCipher#updateGranularity}. The rest will be held
     * until the next update or doFinal call.
     */
    private byte[] buffer;

    private BotanBlockCipher(String name, CipherMode cipherMode, int blockSize) {
        this.name = Objects.requireNonNull(name);
        this.cipherMode = Objects.requireNonNull(cipherMode);
        this.blockSize = blockSize;
        this.cipherRef = new PointerByReference();
    }

    /**
     * Gets the native botan cipher name (e.g. 'AES-128/CBC/PKCS7').
     *
     * @param padding padding algorithm
     * @param keySize the key size
     * @return {@link String} containing the Botan cipher name.
     */
    abstract String getBotanCipherName(String padding, int keySize);

    /**
     * Whether the operation modes requires data block aligned or not.
     *
     * @return {@code true} if data must be block size aligned, {@code false} otherwise.
     */
    abstract boolean requiresDataBlockAligned();

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("Cipher mode not supported " + mode);
    }

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
        if (cipherMode.isAuthenticated()) {
            return Math.addExact(inputLen, (tLen / Byte.SIZE));
        }

        if (isWithoutPadding() || isDecrypting(mode)) {
            return inputLen;
        }

        final NativeLongByReference outputSize = new NativeLongByReference();
        final int err = singleton().botan_cipher_output_length(cipherRef.getValue(), inputLen, outputSize);
        checkNativeCall(err, "botan_cipher_output_length");

        final int result = Math.addExact(inputLen, blockSize);
        return Math.subtractExact(result, (inputLen % blockSize));
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters parameters = null;

        if (iv != null && iv.length > 0) {
            try {
                parameters = AlgorithmParameters.getInstance(name);
                parameters.init(new IvParameterSpec(iv));

            } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                parameters = null;
            }
        }

        return parameters;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        final byte[] encodedKey = checkSecretKey(key);
        final int keySize = encodedKey.length;

        final String algName = getBotanCipherName(padding.getName(), encodedKey.length);
        final NativeLongByReference updateGranularity = new NativeLongByReference();

        // Translate java cipher mode to botan native mode (0: Encryption, 1: Decryption)
        this.mode = Math.subtractExact(opmode, 1);
        this.buffer = EMPTY_BYTE_ARRAY;

        int err = singleton().botan_cipher_init(cipherRef, algName, mode);
        checkNativeCall(err, "botan_cipher_init");

        BotanUtil.FourParameterFunction<Pointer, NativeLongByReference> getKeySpec = (a, b, c, d) -> {
            return singleton().botan_cipher_get_keyspec(a, b, c, d);
        };

        checkKeySize(cipherRef.getValue(), keySize, getKeySpec);

        err = singleton().botan_cipher_set_key(cipherRef.getValue(), encodedKey, keySize);
        checkNativeCall(err, "botan_cipher_set_key");

        err = singleton().botan_cipher_get_update_granularity(cipherRef.getValue(), updateGranularity);
        checkNativeCall(err, "botan_cipher_get_update_granularity");

        this.updateGranularity = updateGranularity.intValue();
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);

        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();

            if (!cipherMode.isAuthenticated()) {
                final int err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
                checkNativeCall(err, "botan_cipher_start");
            }
        } else if (params instanceof GCMParameterSpec) {
            iv = ((GCMParameterSpec) params).getIV();
            tLen = ((GCMParameterSpec) params).getTLen();

            if (CipherMode.GCM == cipherMode && tLen != 128) {
                // TODO: Botan allow any of the values 128, 120, 112, 104, or 96 bits as a tag size.
                throw new InvalidAlgorithmParameterException("Invalid tag length: " + tLen);
            }

            if (CipherMode.EAX == cipherMode && tLen != 128) {
                // TODO: check allowed tLen for EAX
                throw new InvalidAlgorithmParameterException("Invalid tag length: " + tLen);
            }

            if (CipherMode.CCM == cipherMode && (iv.length < 7 || iv.length > 13)) {
                // TODO: allow CCM dynamic parameters
                throw new InvalidAlgorithmParameterException("IV size must be between 7 and 13");
            }

            if (CipherMode.OCB == cipherMode && iv.length > 15) {
                throw new InvalidAlgorithmParameterException("Max allowed IV size 15");
            }
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            final IvParameterSpec parameterSpec = params.getParameterSpec(IvParameterSpec.class);
            engineInit(opmode, key, parameterSpec, random);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException("Parameters must be convertible to IvParameterSpec", e);
        }
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        if (CipherMode.GCM != cipherMode && CipherMode.SIV != cipherMode) {
            String format = "Cipher '%s' does not support this method for mode '%s'.";
            throw new UnsupportedOperationException(String.format(format, name, cipherMode));
        }

        final byte[] fromOffset = Arrays.copyOfRange(src, offset, src.length);

        int err = singleton().botan_cipher_set_associated_data(cipherRef.getValue(), fromOffset, len);
        checkNativeCall(err, "botan_cipher_set_associated_data");

        if (isNullOrEmpty(iv)) {
            if (CipherMode.GCM == cipherMode) {
                throw new IllegalArgumentException(ERR_MSG_GCM_WITHOUT_IV);
            } else {
                err = singleton().botan_cipher_start(cipherRef.getValue(), EMPTY_BYTE_ARRAY, 0);
                checkNativeCall(err, "botan_cipher_start");
            }
        } else {
            err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");
        }

        if (isNullOrEmpty(iv)) {
            tLen = 128;
        }

        canStart = true;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        final byte[] result = engineUpdate(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);

        return result.length;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (inputLen == 0) {
            return EMPTY_BYTE_ARRAY;
        }

        // resize buffer and append the new input
        byte[] currentInput = Arrays.copyOf(buffer, Math.addExact(inputLen, buffer.length));
        System.arraycopy(input, inputOffset, currentInput, buffer.length, inputLen);

        // compute the new buffer offset
        int bufferOffset = currentInput.length % updateGranularity;

        final int index = Math.subtractExact(currentInput.length, bufferOffset);
        input = Arrays.copyOfRange(currentInput, 0, index);
        buffer = Arrays.copyOfRange(currentInput, index, currentInput.length);

        return (input.length == 0) ? EMPTY_BYTE_ARRAY
                : doCipher(input, 0, input.length, BOTAN_UPDATE_FLAG);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws IllegalBlockSizeException {
        final byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);

        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException {
        boolean isBlockSizeAligned = Math.addExact(inputLen, buffer.length) % blockSize == 0;
        if (isWithoutPadding() && requiresDataBlockAligned() && !isBlockSizeAligned) {
            throw new IllegalBlockSizeException("Data not block size aligned");
        }

        return doCipher(input, inputOffset, inputLen, BOTAN_DO_FINAL_FLAG);
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

        if (cipherMode.isAuthenticated() && !canStart) {
            startAeadMode();
        }

        final NativeLongByReference outputWritten = new NativeLongByReference();
        final NativeLongByReference inputConsumed = new NativeLongByReference();

        final byte[] finalInput = getDoFinalInput(input, inputOffset, inputLen);
        final byte[] output = new byte[engineGetOutputSize(Math.addExact(inputLen, buffer.length))];

        final int err = singleton().botan_cipher_update(cipherRef.getValue(), botanFlag,
                output, output.length, outputWritten,
                finalInput, finalInput.length, inputConsumed);

        checkNativeCall(err, "botan_cipher_update");

        final byte[] result = Arrays.copyOfRange(output, 0, outputWritten.intValue());

        if (BOTAN_DO_FINAL_FLAG == botanFlag) {
            engineReset();
        }

        return result;
    }

    private void engineReset() {
        int err = singleton().botan_cipher_reset(cipherRef.getValue());
        checkNativeCall(err, "botan_cipher_reset");

        buffer = EMPTY_BYTE_ARRAY;

        if (iv != null) {
            //FIXME: nonce reuse - disable starting cipher with same IV
            err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");
        }
    }

    private byte[] getDoFinalInput(byte[] input, int inputOffset, int inputLen) {
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

    private void startAeadMode() {
        if (isNullOrEmpty(iv)) {
            if (CipherMode.GCM == cipherMode) {
                throw new IllegalArgumentException(ERR_MSG_GCM_WITHOUT_IV);
            }

            // Set default tag length when no IV is supplied
            tLen = 128;

            final int err = singleton().botan_cipher_start(cipherRef.getValue(), EMPTY_BYTE_ARRAY, 0);
            checkNativeCall(err, "botan_cipher_start");
        } else {
            final int err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");
        }
    }

    private boolean isWithoutPadding() {
        return PaddingAlgorithm.NO_PADDING == padding;
    }

    private static boolean isDecrypting(int mode) {
        return mode == 1;
    }

    private static boolean isNullOrEmpty(byte[] value) {
        return value == null || value.length == 0;
    }

    // AES
    public static final class AesCbc extends BotanBlockCipher {

        public AesCbc() {
            super("AES", CipherMode.CBC, 16);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return String.format("AES-%d/CBC/%s", keySize * Byte.SIZE, padding);
        }

        @Override
        boolean requiresDataBlockAligned() {
            return true;
        }

    }

    public static final class AesCfb extends BotanBlockCipher {

        public AesCfb() {
            super("AES", CipherMode.CFB, 16);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return String.format("AES-%d/CFB", keySize * Byte.SIZE);
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class AesOfb extends BotanBlockCipher {

        public AesOfb() {
            super("AES", CipherMode.OFB, 16);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return String.format("AES-%d/OFB", keySize * Byte.SIZE);
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class AesCtr extends BotanBlockCipher {

        public AesCtr() {
            super("AES", CipherMode.CTR, 16);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return String.format("AES-%d/CTR", keySize * Byte.SIZE);
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class AesGcm extends BotanBlockCipher {

        public AesGcm() {
            super("AES", CipherMode.GCM, 16);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return String.format("AES-%d/GCM(16)", keySize * Byte.SIZE);
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class AesCcm extends BotanBlockCipher {

        public AesCcm() {
            super("AES", CipherMode.CCM, 16);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return String.format("AES-%d/CCM(16,3)", keySize * Byte.SIZE);
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class AesSiv extends BotanBlockCipher {

        public AesSiv() {
            super("AES", CipherMode.SIV, 16);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return String.format("AES-%d/SIV", (keySize / 2) * Byte.SIZE);
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class AesEax extends BotanBlockCipher {

        public AesEax() {
            super("AES", CipherMode.EAX, 16);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return String.format("AES-%d/EAX", keySize * Byte.SIZE);
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class AesOcb extends BotanBlockCipher {

        public AesOcb() {
            super("AES", CipherMode.OCB, 16);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return String.format("AES-%d/OCB", keySize * Byte.SIZE);
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    // DES
    public static final class DesCbc extends BotanBlockCipher {
        public DesCbc() {
            super("DES", CipherMode.CBC, 8);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return "DES/CBC/" + padding;
        }

        @Override
        boolean requiresDataBlockAligned() {
            return true;
        }

    }

    public static final class DesCfb extends BotanBlockCipher {
        public DesCfb() {
            super("DES", CipherMode.CFB, 8);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return "DES/CFB";
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class DesOfb extends BotanBlockCipher {
        public DesOfb() {
            super("DES", CipherMode.OFB, 8);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return "DES/OFB";
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class DesCtr extends BotanBlockCipher {
        public DesCtr() {
            super("DES", CipherMode.CTR, 8);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return "DES/CTR";
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    // 3DES
    public static final class DesEdeCbc extends BotanBlockCipher {
        public DesEdeCbc() {
            super("DESede", CipherMode.CBC, 8);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return "3DES/CBC/" + padding;
        }

        @Override
        boolean requiresDataBlockAligned() {
            return true;
        }

    }

    public static final class DesEdeCfb extends BotanBlockCipher {
        public DesEdeCfb() {
            super("DESede", CipherMode.CFB, 8);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return "3DES/CFB";
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class DesEdeOfb extends BotanBlockCipher {
        public DesEdeOfb() {
            super("DESede", CipherMode.OFB, 8);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return "3DES/OFB";
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

    public static final class DesEdeCtr extends BotanBlockCipher {
        public DesEdeCtr() {
            super("DESede", CipherMode.CTR, 8);
        }

        @Override
        String getBotanCipherName(String padding, int keySize) {
            return "3DES/CTR";
        }

        @Override
        boolean requiresDataBlockAligned() {
            return false;
        }

    }

}
