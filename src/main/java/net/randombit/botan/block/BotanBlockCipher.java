/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.block;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;

import java.security.spec.AlgorithmParameterSpec;

import static net.randombit.botan.Botan.singleton;

public abstract class BotanBlockCipher extends CipherSpi {

    /**
     * Calling botan_cipher_update() for sending more input.
     */
    private static final int BOTAN_UPDATE_FLAG = 0;

    /**
     * Calling botan_cipher_update() for finishing cipher operation.
     */
    private static final int BOTAN_DO_FINAL_FLAG = 1;

    /**
     * Holds the name of the block cipher algorithm (e.g. AES-256/CBC/PKCS7).
     */
    private final String name;

    /**
     * Holds the block size of the cipher in bytes.
     */
    private final int blockSize;

    /**
     * Whether this modes is with padding or not
     */
    private boolean withPadding;

    /**
     * Holds the reference to the block cipher object referenced by botan.
     */
    private final PointerByReference cipherRef;

    /**
     * Holds the cipher operation mode in native botan terms (0: Encryption, 1: Decryption)
     */
    private int mode;

    /**
     * Holds the Initial Vector (IV).
     */
    private byte[] iv;

    private BotanBlockCipher(String name, int blockSize, boolean withPadding) {
        this.name = Objects.requireNonNull(name);
        this.blockSize = blockSize;
        this.withPadding = withPadding;
        this.cipherRef = new PointerByReference();
    }

    /**
     * Gets the standard name for the particular algorithm (e.g. AES).
     *
     * @return {@link String} containing the base cipher name
     */
    abstract String getCipherName();

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("Cipher mode not supported " + mode);
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("Padding algorithm not supported " + padding);
    }

    @Override
    protected int engineGetBlockSize() {
        return blockSize;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (!withPadding || mode == 1) {
            return inputLen;
        }

        final NativeLongByReference outputSize = new NativeLongByReference();
        singleton().botan_cipher_output_length(cipherRef.getValue(), inputLen, outputSize);

        return inputLen + (blockSize - inputLen % blockSize);
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
                parameters = AlgorithmParameters.getInstance(getCipherName());
                parameters.init(new IvParameterSpec(iv));

            } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                parameters = null;
            }
        }

        return parameters;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        final byte[] encodedKey = checkKey(key);
        final long keySize = encodedKey.length;

        final String algName = String.format(name, keySize * Byte.SIZE);

        // Translate java cipher mode to botan native mode (0: Encryption, 1: Decryption)
        this.mode = opmode - 1;

        singleton().botan_cipher_init(cipherRef, algName, mode);
        singleton().botan_cipher_set_key(cipherRef.getValue(), encodedKey, keySize);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException {
        engineInit(opmode, key, random);

        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();
            singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
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
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        throw new UnsupportedOperationException("Only doFinal(input) is currently supported");
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new UnsupportedOperationException("Only doFinal(input) is currently supported");
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws IllegalBlockSizeException {
        output = engineDoFinal(input, inputOffset, inputLen);

        return output.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException {
        if (!withPadding && (inputLen % blockSize) != 0) {
            throw new IllegalBlockSizeException("Data not block size aligned");
        }

        return doCipher(input, inputOffset, inputLen, BOTAN_DO_FINAL_FLAG);
    }

    private byte[] doCipher(byte[] input, int inputOffset, int inputLen, int botanFlag) {
        if (inputLen == 0) {
            return new byte[0];
        }

        final NativeLongByReference outputWritten = new NativeLongByReference();
        final NativeLongByReference inputConsumed = new NativeLongByReference();
        final byte[] output = new byte[engineGetOutputSize(inputLen)];

        final byte[] inputFromOffset = input == null ?
                new byte[0] : Arrays.copyOfRange(input, inputOffset, input.length);

        singleton().botan_cipher_update(cipherRef.getValue(), botanFlag,
                output, output.length, outputWritten,
                inputFromOffset, inputLen, inputConsumed);

        if (BOTAN_DO_FINAL_FLAG == botanFlag) {
            engineReset();
        }

        return Arrays.copyOfRange(output, 0, outputWritten.intValue());
    }

    private byte[] checkKey(Key key) throws InvalidKeyException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Only SecretKey is supported");
        }

        final byte[] encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new InvalidKeyException("key.getEncoded() == null");
        }

        return encodedKey;
    }

    private void engineReset() {
        singleton().botan_cipher_reset(cipherRef.getValue());
        if (iv != null) {
            singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
        }
    }

    // AES
    public static final class AesCbcNoPadding extends BotanBlockCipher {
        public AesCbcNoPadding() {
            super("AES-%d/CBC/NoPadding", 16, false);
        }

        public String getCipherName() {
            return "AES";
        }

    }

    public static final class AesCbcPkcs7 extends BotanBlockCipher {
        public AesCbcPkcs7() {
            super("AES-%d/CBC/PKCS7", 16, true);
        }

        public String getCipherName() {
            return "AES";
        }
    }

    public static final class AesCbcIso extends BotanBlockCipher {
        public AesCbcIso() {
            super("AES-%d/CBC/OneAndZeros", 16, true);
        }

        public String getCipherName() {
            return "AES";
        }
    }

    public static final class AesCbcX923 extends BotanBlockCipher {
        public AesCbcX923() {
            super("AES-%d/CBC/X9.23", 16, true);
        }

        public String getCipherName() {
            return "AES";
        }
    }

    public static final class AesCbcEsp extends BotanBlockCipher {
        public AesCbcEsp() {
            super("AES-%d/CBC/ESP", 16, true);
        }

        String getCipherName() {
            return "AES";
        }
    }

    // DES
    public static final class DesCbcNoPadding extends BotanBlockCipher {
        public DesCbcNoPadding() {
            super("DES/CBC/NoPadding", 8, false);
        }

        public String getCipherName() {
            return "DES";
        }
    }

    public static final class DesCbcPkcs7 extends BotanBlockCipher {
        public DesCbcPkcs7() {
            super("DES/CBC/PKCS7", 8, true);
        }

        public String getCipherName() {
            return "DES";
        }
    }

    public static final class DesCbcX923 extends BotanBlockCipher {
        public DesCbcX923() {
            super("DES/CBC/X9.23", 8, true);
        }

        public String getCipherName() {
            return "DES";
        }
    }

    public static final class DesCbcEsp extends BotanBlockCipher {
        public DesCbcEsp() {
            super("DES/CBC/ESP", 8, true);
        }

        public String getCipherName() {
            return "DES";
        }
    }

    // 3DES
    public static final class DesEdeCbcNoPadding extends BotanBlockCipher {
        public DesEdeCbcNoPadding() {
            super("3DES/CBC/NoPadding", 8, false);
        }

        public String getCipherName() {
            return "DESede";
        }
    }

    public static final class DesEdeCbcPkcs7 extends BotanBlockCipher {
        public DesEdeCbcPkcs7() {
            super("3DES/CBC/PKCS7", 8, true);
        }

        public String getCipherName() {
            return "DESede";
        }
    }

    public static final class DesEdeCbcX923 extends BotanBlockCipher {
        public DesEdeCbcX923() {
            super("3DES/CBC/X9.23", 8, true);
        }

        public String getCipherName() {
            return "DESede";
        }
    }

    public static final class DesEdeCbcEsp extends BotanBlockCipher {
        public DesEdeCbcEsp() {
            super("3DES/CBC/ESP", 8, true);
        }

        public String getCipherName() {
            return "DESede";
        }
    }

}
