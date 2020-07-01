/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.stream;

import static net.randombit.botan.Botan.checkNativeCall;
import static net.randombit.botan.Botan.singleton;
import static net.randombit.botan.Constants.BOTAN_DO_FINAL_FLAG;
import static net.randombit.botan.Constants.BOTAN_UPDATE_FLAG;
import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;

import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
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

import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;

public class BotanStreamCipher extends CipherSpi {

    /**
     * Holds the name of the cipher algorithm.
     */
    private final String name;

    /**
     * Holds the reference to the cipher object referenced by botan.
     */
    private final PointerByReference cipherRef;

    /**
     * Holds the Initial Vector (IV).
     */
    private byte[] iv;

    private BotanStreamCipher(String name) {
        this.name = Objects.requireNonNull(name);
        this.cipherRef = new PointerByReference();
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("No cipher modes allowed for stream ciphers!");
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("No padding algorithms allowed for stream ciphers!");
    }

    @Override
    protected int engineGetBlockSize() {
        return 1;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return inputLen;
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
        final byte[] encodedKey = checkKey(key);
        final long keySize = encodedKey.length;

        int err = singleton().botan_cipher_init(cipherRef, name, Math.subtractExact(opmode, 1));
        checkNativeCall(err, "botan_cipher_init");

        checkKeySize(keySize);

        err = singleton().botan_cipher_set_key(cipherRef.getValue(), encodedKey, keySize);
        checkNativeCall(err, "botan_cipher_set_key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        engineInit(opmode, key, random);

        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();

            final int err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");
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
        final byte[] result = engineUpdate(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);

        return result.length;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return doCipher(input, inputOffset, inputLen, BOTAN_UPDATE_FLAG);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        final byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);

        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return doCipher(input, inputOffset, inputLen, BOTAN_DO_FINAL_FLAG);
    }

    private byte[] doCipher(byte[] input, int inputOffset, int inputLen, int botanFlag) {
        if (input.length == 0) {
            return EMPTY_BYTE_ARRAY;
        }

        final NativeLongByReference outputWritten = new NativeLongByReference();
        final NativeLongByReference inputConsumed = new NativeLongByReference();

        final byte[] output = new byte[inputLen];
        final byte[] inputFromOffset = Arrays.copyOfRange(input, inputOffset, Math.addExact(inputOffset, inputLen));

        final int err = singleton().botan_cipher_update(cipherRef.getValue(), botanFlag,
                output, output.length, outputWritten,
                inputFromOffset, inputLen, inputConsumed);

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

        if (iv != null) {
            //TODO: nonce reuse ?
            err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");
        }
    }

    private static byte[] checkKey(Key key) throws InvalidKeyException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Only SecretKey is supported");
        }

        final byte[] encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new InvalidKeyException("key.getEncoded() == null");
        }

        return encodedKey;
    }

    private void checkKeySize(long keySize) throws InvalidKeyException {
        final NativeLongByReference minimumLength = new NativeLongByReference();
        final NativeLongByReference maximumLength = new NativeLongByReference();
        final NativeLongByReference lengthModulo = new NativeLongByReference();

        final int err = singleton().botan_cipher_get_keyspec(cipherRef.getValue(), minimumLength, maximumLength,
                lengthModulo);
        checkNativeCall(err, "botan_cipher_get_keyspec");

        if (keySize < minimumLength.intValue()) {
            throw new InvalidKeyException("key.getEncoded() < minimum key length: " + minimumLength.intValue());
        }

        if (keySize > maximumLength.intValue()) {
            throw new InvalidKeyException("key.getEncoded() > maximum key length: " + maximumLength.intValue());
        }

        if (keySize % lengthModulo.intValue() != 0) {
            throw new InvalidKeyException("key.getEncoded() not multiple of key length modulo: "
                    + lengthModulo.intValue());
        }

    }

    // Salsa20
    public static final class Salsa20 extends BotanStreamCipher {
        public Salsa20() {
            super("Salsa20");
        }

    }

    // ChaCha20
    public static final class ChaCha20 extends BotanStreamCipher {
        public ChaCha20() {
            super("ChaCha(20)");
        }

    }

}
