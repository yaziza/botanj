/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.block;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import jnr.ffi.byref.PointerByReference;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import static net.randombit.botan.Botan.singleton;

public class BotanBlockCipher extends CipherSpi {

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
     * Holds the key size of the cipher in bytes.
     */
    private int keySize;

    /**
     * Holds the actual mode (encryption / decryption)
     */
    private int opmode;

    private BotanBlockCipher(String name, int blockSize) {
        this.name = name;
        this.blockSize = blockSize;
        this.cipherRef = new PointerByReference();
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {

    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {

    }

    @Override
    protected int engineGetBlockSize() {
        return blockSize;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        final byte[] encodedKey = key.getEncoded();
        this.opmode = opmode;
        this.keySize = encodedKey.length;

        int err = singleton().botan_block_cipher_init(cipherRef, name + keySize * 8);
        if (err != 0) {
            String msg = singleton().botan_error_description(err);
            throw new InvalidKeyException(msg);
        }

        err = singleton().botan_block_cipher_set_key(cipherRef.getValue(), encodedKey, encodedKey.length);
        if (err != 0) {
            String msg = singleton().botan_error_description(err);
            throw new InvalidKeyException(msg);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return doCipher(input, inputOffset, inputLen);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {

        output = engineUpdate(input, inputOffset, inputLen);
        outputOffset = 0;

        return output.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {

        return doCipher(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        output = engineDoFinal(input, inputOffset, inputLen);
        outputOffset = 0;

        return output.length;
    }

    private byte[] doCipher(byte[] input, int inputOffset, int inputLen) {
        final byte[] fromOffset = Arrays.copyOfRange(input, inputOffset, input.length);
        final int nrOfBlocks = fromOffset.length % blockSize == 0
                ? fromOffset.length / blockSize
                : (fromOffset.length / blockSize) + 1;

        final byte[] output = new byte[nrOfBlocks * blockSize];

        if (Cipher.ENCRYPT_MODE == opmode) {
            singleton().botan_block_cipher_encrypt_blocks(
                    cipherRef.getValue(), fromOffset, output, nrOfBlocks);

        } else if (Cipher.DECRYPT_MODE == opmode) {
            singleton().botan_block_cipher_decrypt_blocks(
                    cipherRef.getValue(), fromOffset, output, nrOfBlocks);

        } else {
            throw new UnsupportedOperationException("Unsupported cipher mode " + opmode + "for algorithm " + name);
        }

        return output;
    }

    public static final class Aes extends BotanBlockCipher {
        public Aes() {
            super("AES-", 16);
        }
    }

}
