/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.stream;

import static net.randombit.botan.BotanInstance.checkNativeCall;
import static net.randombit.botan.BotanInstance.singleton;
import static net.randombit.botan.BotanUtil.checkKeySize;
import static net.randombit.botan.BotanUtil.checkSecretKey;
import static net.randombit.botan.Constants.BOTAN_DO_FINAL_FLAG;
import static net.randombit.botan.Constants.BOTAN_UPDATE_FLAG;
import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;

import javax.crypto.CipherSpi;
import javax.crypto.NoSuchPaddingException;
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

public abstract class BotanStreamCipher extends CipherSpi {

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

    /**
     * Holds the cipher operation mode in native botan terms (0: Encryption, 1: Decryption)
     */
    private int mode;

    /**
     * Whether the eXtended-nonce construction is used.
     *
     * @return {@code true} if the eXtended-nonce is used, {@code false} otherwise.
     */
    abstract boolean withExtendedNonce();

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
        final byte[] encodedKey = checkSecretKey(key);
        final int keySize = encodedKey.length;

        mode = Math.subtractExact(opmode, 1);
        int err = singleton().botan_cipher_init(cipherRef, name, mode);
        checkNativeCall(err, "botan_cipher_init");

        BotanUtil.FourParameterFunction<Pointer, NativeLongByReference> getKeySpec = (a, b, c, d) -> {
            return singleton().botan_cipher_get_keyspec(a, b, c, d);
        };

        checkKeySize(cipherRef.getValue(), keySize, getKeySpec);

        err = singleton().botan_cipher_set_key(cipherRef.getValue(), encodedKey, keySize);
        checkNativeCall(err, "botan_cipher_set_key");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        engineInit(opmode, key, random);

        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();

            if (withExtendedNonce() && iv.length < 24) {
                throw new InvalidAlgorithmParameterException("Nonce size too small for algorithm: " + name);
            }

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

        if (iv != null && isDecrypting(mode)) {
            //TODO: throw exception when reusing cipher without calling init while encrypting
            err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");
        }
    }

    private static boolean isDecrypting(int mode) {
        return mode == 1;
    }

    // Salsa20
    public static final class Salsa20 extends BotanStreamCipher {
        public Salsa20() {
            super("Salsa20");
        }

        public boolean withExtendedNonce() {
            return false;
        }

    }

    public static final class XSalsa20 extends BotanStreamCipher {
        public XSalsa20() {
            super("Salsa20");
        }

        public boolean withExtendedNonce() {
            return true;
        }

    }

    // ChaCha20
    public static final class ChaCha20 extends BotanStreamCipher {
        public ChaCha20() {
            super("ChaCha(20)");
        }

        public boolean withExtendedNonce() {
            return false;
        }

    }

    public static final class XChaCha20 extends BotanStreamCipher {
        public XChaCha20() {
            super("ChaCha(20)");
        }

        public boolean withExtendedNonce() {
            return true;
        }

    }

}
