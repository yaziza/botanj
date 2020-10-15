/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey;

import static net.randombit.botan.jnr.BotanInstance.checkNativeCall;
import static net.randombit.botan.jnr.BotanInstance.singleton;
import static net.randombit.botan.BotanUtil.checkKeySize;
import static net.randombit.botan.BotanUtil.checkSecretKey;

import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Objects;

import jnr.ffi.Pointer;
import jnr.ffi.byref.NativeLongByReference;
import jnr.ffi.byref.PointerByReference;
import net.randombit.botan.BotanUtil;

public abstract class BotanBaseAsymmetricCipher extends CipherSpi {

    /**
     * Holds the reference to the cipher object referenced by botan.
     */
    protected final PointerByReference cipherRef;

    /**
     * Holds the name of the cipher algorithm.
     */
    protected final String name;

    /**
     * Holds the Initial Vector (IV).
     */
    protected byte[] iv;

    /**
     * Holds the cipher operation mode in native botan terms (0: Encryption, 1: Decryption)
     */
    protected int mode;

    protected BotanBaseAsymmetricCipher(String name) {
        this.name = Objects.requireNonNull(name);
        this.cipherRef = new PointerByReference();
    }

    protected static boolean isDecrypting(int mode) {
        return mode == 1;
    }

    /**
     * Gets the native botan cipher name (e.g. 'AES-128/CBC/PKCS7').
     *
     * @param keyLength the key length
     * @return {@link String} containing the Botan cipher name.
     */
    protected abstract String getBotanCipherName(int keyLength);

    /**
     * Checks whether the given nonce size is supported.
     *
     * @param nonceLength the nonce length
     * @return {@code True} is the given nonce length is supported, {@code False} otherwise.
     */
    protected abstract boolean isValidNonceLength(int nonceLength);

    protected void engineReset() {
        int err = singleton().botan_cipher_reset(cipherRef.getValue());
        checkNativeCall(err, "botan_cipher_reset");

        if (iv != null) {
            //FIXME: nonce reuse - disable starting cipher with same IV
            err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        throw new NoSuchAlgorithmException("Cipher mode not supported " + mode);
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
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        engineInit(opmode, key, random);

        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();

            if (!isValidNonceLength(iv.length * Byte.SIZE)) {
                String msg = String.format("Nonce with length %d not allowed for algorithm %s", iv.length, name);
                throw new InvalidAlgorithmParameterException(msg);
            }

            final int err = singleton().botan_cipher_start(cipherRef.getValue(), iv, iv.length);
            checkNativeCall(err, "botan_cipher_start");

        } else {
            throw new InvalidAlgorithmParameterException("Error: Missing or invalid IvParameterSpec provided !");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        final byte[] encodedKey = checkSecretKey(key);
        final int keySize = encodedKey.length;

        final String algName = getBotanCipherName(keySize);

        // Translate java cipher mode to botan native mode (0: Encryption, 1: Decryption)
        mode = Math.subtractExact(opmode, 1);

        int err = singleton().botan_cipher_init(cipherRef, algName, mode);
        checkNativeCall(err, "botan_cipher_init");

        BotanUtil.FourParameterFunction<Pointer, NativeLongByReference> getKeySpec = (a, b, c, d) -> {
            return singleton().botan_cipher_get_keyspec(a, b, c, d);
        };

        checkKeySize(cipherRef.getValue(), keySize, getKeySpec);

        err = singleton().botan_cipher_set_key(cipherRef.getValue(), encodedKey, keySize);
        checkNativeCall(err, "botan_cipher_set_key");
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        final byte[] result = engineUpdate(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);

        return result.length;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws IllegalBlockSizeException {
        final byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);

        return result.length;
    }

    @Override
    protected abstract byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException;

}
