/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.seckey.stream;

import static net.randombit.botan.Constants.BOTAN_DO_FINAL_FLAG;
import static net.randombit.botan.Constants.BOTAN_UPDATE_FLAG;
import static net.randombit.botan.Constants.EMPTY_BYTE_ARRAY;
import static net.randombit.botan.util.BotanUtil.isNullOrEmpty;

import javax.crypto.NoSuchPaddingException;
import java.util.Arrays;

import net.randombit.botan.seckey.BotanBaseAsymmetricCipher;

public abstract class BotanStreamCipher extends BotanBaseAsymmetricCipher {

    private BotanStreamCipher(String name) {
        super(name);
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        throw new NoSuchPaddingException("Padding algorithm not allowed for stream cipher!");
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
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return doCipher(input, inputOffset, inputLen, BOTAN_UPDATE_FLAG);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        return doCipher(input, inputOffset, inputLen, BOTAN_DO_FINAL_FLAG);
    }

    private byte[] doCipher(byte[] input, int inputOffset, int inputLen, int botanFlag) {
        if (isNullOrEmpty(input) || inputLen == 0) {
            return EMPTY_BYTE_ARRAY;
        }

        final byte[] inputFromOffset = Arrays.copyOfRange(input, inputOffset, Math.addExact(inputOffset, inputLen));

        return super.doCipher(inputFromOffset, inputLen, botanFlag);
    }

    // Salsa20
    public static final class Salsa20 extends BotanStreamCipher {
        public Salsa20() {
            super("Salsa20");
        }

        protected String getBotanCipherName(int keyLength) {
            return "Salsa20";
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength == 8 || nonceLength == 24;
        }
    }

    public static final class XSalsa20 extends BotanStreamCipher {
        public XSalsa20() {
            super("Salsa20");
        }

        protected String getBotanCipherName(int keyLength) {
            return "Salsa20";
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength == 24;
        }
    }

    // ChaCha20
    public static final class ChaCha20 extends BotanStreamCipher {
        public ChaCha20() {
            super("ChaCha(20)");
        }

        protected String getBotanCipherName(int keyLength) {
            return "ChaCha(20)";
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength == 8 || nonceLength == 12 || nonceLength == 24;
        }
    }

    public static final class XChaCha20 extends BotanStreamCipher {
        public XChaCha20() {
            super("ChaCha(20)");
        }

        protected String getBotanCipherName(int keyLength) {
            return "ChaCha(20)";
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength == 24;
        }
    }

    // CTR mode
    public static final class AesCtr extends BotanStreamCipher {
        public AesCtr() {
            super("AES");
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return String.format("AES-%d/CTR", keyLength * Byte.SIZE);
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength >= 0 && nonceLength <= 16;
        }
    }

    public static final class DesCtr extends BotanStreamCipher {
        public DesCtr() {
            super("DES");
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return "DES/CTR";
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength >= 0 && nonceLength <= 8;
        }
    }

    public static final class DesEdeCtr extends BotanStreamCipher {
        public DesEdeCtr() {
            super("3DES");
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return "3DES/CTR";
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength >= 0 && nonceLength <= 8;
        }
    }

    // OFB mode
    public static final class AesOfb extends BotanStreamCipher {
        public AesOfb() {
            super("AES");
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return String.format("AES-%d/OFB", keyLength * Byte.SIZE);
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength >= 0 && nonceLength <= 16;
        }
    }

    public static final class DesOfb extends BotanStreamCipher {
        public DesOfb() {
            super("DES");
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return "DES/OFB";
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength >= 0 && nonceLength <= 8;
        }
    }

    public static final class DesEdeOfb extends BotanStreamCipher {
        public DesEdeOfb() {
            super("3DES");
        }

        @Override
        protected String getBotanCipherName(int keyLength) {
            return "3DES/OFB";
        }

        @Override
        protected boolean isValidNonceLength(int nonceLength) {
            return nonceLength >= 0 && nonceLength <= 8;
        }
    }

}
