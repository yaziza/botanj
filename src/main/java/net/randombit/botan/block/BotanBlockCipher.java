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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;

import java.security.spec.AlgorithmParameterSpec;

import static net.randombit.botan.Botan.singleton;

public abstract class BotanBlockCipher extends CipherSpi {

    /**
     * Holds the name of the block cipher algorithm.
     */
    private final String name;

    /**
     * Holds the block size of the cipher in bytes.
     */
    private final int blockSize;

    /**
     * Holds the reference to the block cipher object referenced by botan.
     */
    private final PointerByReference cipherRef;

    /**
     * Holds the Initial Vector (IV).
     */
    private byte[] iv;

    private BotanBlockCipher(String name, int blockSize) {
        this.name = Objects.requireNonNull(name);
        this.blockSize = blockSize;
        this.cipherRef = new PointerByReference();
    }

    /**
     * Gets the standard name for the particular algorithm (e.g. AES).
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
        final NativeLongByReference outputSize = new NativeLongByReference();

        singleton().botan_cipher_output_length(cipherRef.getValue(), inputLen, outputSize);

        return outputSize.intValue();
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

        singleton().botan_cipher_clear(cipherRef.getValue());
        singleton().botan_cipher_init(cipherRef, algName, opmode - 1);
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
        output = engineUpdate(input, inputOffset, inputLen);
        outputOffset = 0;

        return output.length;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return doCipher(input, inputOffset, inputLen);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        if (inputLen <= 0) {
            return new byte[0];
        }

        return doCipher(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        output = engineDoFinal(input, inputOffset, inputLen);
        outputOffset = 0;

        return output.length;
    }

    private byte[] doCipher(byte[] input, int inputOffset, int inputLen) {
        Objects.requireNonNull(input);

        final NativeLongByReference outputSize = new NativeLongByReference();
        singleton().botan_cipher_output_length(cipherRef.getValue(), inputLen, outputSize);

        final byte[] inputFromOffset = Arrays.copyOfRange(input, inputOffset, input.length);
        final byte[] output = new byte[outputSize.intValue()];

        NativeLongByReference outputWritten = new NativeLongByReference();
        NativeLongByReference inputConsumed = new NativeLongByReference();

        int err = singleton().botan_cipher_update(cipherRef.getValue(), 0,
                output, outputSize.intValue(), outputWritten,
                inputFromOffset, inputLen, inputConsumed);

        return output;
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

    // AES
    public static final class AesCbcNoPadding extends BotanBlockCipher {
        public AesCbcNoPadding() {
            super("AES-%d/CBC/NoPadding", 16);
        }

        public String getCipherName() {
            return "AES";
        }

    }

    public static final class AesCbcPkcs7 extends BotanBlockCipher {
        public AesCbcPkcs7() {
            super("AES-%d/CBC/PKCS7", 16);
        }

        public String getCipherName() {
            return "AES";
        }
    }

    public static final class AesCbcIso extends BotanBlockCipher {
        public AesCbcIso() {
            super("AES-%d/CBC/OneAndZeros", 16);
        }

        public String getCipherName() {
            return "AES";
        }
    }

    public static final class AesCbcX923 extends BotanBlockCipher {
        public AesCbcX923() {
            super("AES-%d/CBC/X9.23", 16);
        }

        public String getCipherName() {
            return "AES";
        }
    }

    public static final class AesCbcEsp extends BotanBlockCipher {
        public AesCbcEsp() {
            super("AES-%d/CBC/ESP", 16);
        }

        String getCipherName() {
            return "AES";
        }
    }

    // DES
    public static final class DesCbcNoPadding extends BotanBlockCipher {
        public DesCbcNoPadding() {
            super("DES/CBC/NoPadding", 8);
        }

        public String getCipherName() {
            return "DES";
        }
    }

    public static final class DesCbcPkcs7 extends BotanBlockCipher {
        public DesCbcPkcs7() {
            super("DES/CBC/PKCS7", 8);
        }

        public String getCipherName() {
            return "DES";
        }
    }

    public static final class DesCbcX923 extends BotanBlockCipher {
        public DesCbcX923() {
            super("DES/CBC/X9.23", 8);
        }

        public String getCipherName() {
            return "DES";
        }
    }

    public static final class DesCbcEsp extends BotanBlockCipher {
        public DesCbcEsp() {
            super("DES/CBC/ESP", 8);
        }

        public String getCipherName() {
            return "DES";
        }
    }

    // 3DES
    public static final class DesEdeCbcNoPadding extends BotanBlockCipher {
        public DesEdeCbcNoPadding() {
            super("3DES/CBC/NoPadding", 8);
        }

        public String getCipherName() {
            return "DESede";
        }
    }

    public static final class DesEdeCbcPkcs7 extends BotanBlockCipher {
        public DesEdeCbcPkcs7() {
            super("3DES/CBC/PKCS7", 8);
        }

        public String getCipherName() {
            return "DESede";
        }
    }

    public static final class DesEdeCbcX923 extends BotanBlockCipher {
        public DesEdeCbcX923() {
            super("3DES/CBC/X9.23", 8);
        }

        public String getCipherName() {
            return "DESede";
        }
    }

    public static final class DesEdeCbcEsp extends BotanBlockCipher {
        public DesEdeCbcEsp() {
            super("3DES/CBC/ESP", 8);
        }

        public String getCipherName() {
            return "DESede";
        }
    }

}
