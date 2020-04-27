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
import javax.crypto.spec.IvParameterSpec;
import net.randombit.botan.BotanProvider;
import net.randombit.botan.codec.HexUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

@RunWith(Parameterized.class)
public class BotanBlockCipherTest {

    @Parameterized.Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                // AES
                {"AES/CBC/NoPadding", 16, 16, true, false},
                {"AES/CBC/NoPadding", 16, 24, true, false},
                {"AES/CBC/NoPadding", 16, 32, true, false},

                // FIXME: PKCS7 padding different than bouncy castle
                {"AES/CBC/PKCS7", 16, 16, false, true},
                {"AES/CBC/PKCS7", 16, 24, false, true},
                {"AES/CBC/PKCS7", 16, 32, false, true},

                // TODO: check if Bouncy castle supports ISO padding
                {"AES/CBC/OneAndZeros", 16, 16, false, true},
                {"AES/CBC/OneAndZeros", 16, 24, false, true},
                {"AES/CBC/OneAndZeros", 16, 32, false, true},

                {"AES/CBC/X9.23", 16, 16, false, true},
                {"AES/CBC/X9.23", 16, 24, false, true},
                {"AES/CBC/X9.23", 16, 32, false, true},

                {"AES/CBC/ESP", 16, 16, false, true},
                {"AES/CBC/ESP", 16, 24, false, true},
                {"AES/CBC/ESP", 16, 32, false, true},

                // DES
                {"DES/CBC/NoPadding", 8, 8, true, false},
                {"DES/CBC/PKCS7", 8, 8, false, true},
                {"DES/CBC/X9.23", 8, 8, false, true},
                {"DES/CBC/ESP", 8, 8, false, true},

                // 3DES
                {"DESede/CBC/NoPadding", 8, 16, true, false},
                {"DESede/CBC/NoPadding", 8, 24, true, false},

                {"DESede/CBC/PKCS7", 8, 16, false, true},
                {"DESede/CBC/PKCS7", 8, 24, false, true},

                {"DESede/CBC/X9.23", 8, 16, false, true},
                {"DESede/CBC/X9.23", 8, 24, false, true},

                {"DESede/CBC/ESP", 8, 16, false, true},
                {"DESede/CBC/ESP", 8, 24, false, true},
        });
    }

    private final String algorithm;
    private final int blockSize;
    private final int keySize;
    private final boolean isSupportedByBouncyCastle;
    private final boolean withPadding;

    public BotanBlockCipherTest(String algorithm, int blockSize, int keySize,
                                boolean isSupportedByBouncyCastle, boolean withPadding) {
        this.algorithm = algorithm;
        this.blockSize = blockSize;
        this.keySize = keySize;
        this.isSupportedByBouncyCastle = isSupportedByBouncyCastle;
        this.withPadding = withPadding;
    }

    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BotanProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testCipherBlockSize() throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

        cipher.init(ENCRYPT_MODE, key);
        cipher.doFinal("top secret input".getBytes());

        Assert.assertEquals(algorithm + " block size in bytes", blockSize, cipher.getBlockSize());
    }

    @Test
    public void testCipherParametersWithIv() throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

        cipher.init(ENCRYPT_MODE, key, iv);
        AlgorithmParameters parameters = cipher.getParameters();

        String baseCipher = algorithm.substring(0, algorithm.indexOf('/'));
        Assert.assertEquals(baseCipher + " mismatch ", baseCipher, parameters.getAlgorithm());
    }

    @Test
    public void testCipherParametersWithoutIv() throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.PROVIDER_NAME);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        cipher.init(ENCRYPT_MODE, key);
        AlgorithmParameters parameters = cipher.getParameters();

        Assert.assertNull("IV supplied", parameters);
    }

    @Test
    public void testEncryptAgainstBouncyCastle() throws GeneralSecurityException {
        if (isSupportedByBouncyCastle) {
            final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
            final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

            final Cipher bc = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final Cipher botan = Cipher.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            bc.init(ENCRYPT_MODE, key, iv);
            botan.init(ENCRYPT_MODE, key, iv);

            final byte[] input = withPadding ? "some plain text".getBytes()
                    : new byte[blockSize * Byte.SIZE * 10];

            final byte[] expected = bc.doFinal(input);
            final byte[] actual = botan.doFinal(input);

            Assert.assertArrayEquals("Encryption mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

    @Test
    public void testDecryptAgainstBouncyCastle() throws GeneralSecurityException {
        if (isSupportedByBouncyCastle) {
            final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
            final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

            final Cipher bc = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final Cipher botan = Cipher.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            bc.init(DECRYPT_MODE, key, iv);
            botan.init(DECRYPT_MODE, key, iv);

            final byte[] input = withPadding ? "some cipher text".getBytes()
                    : new byte[blockSize * Byte.SIZE * 10];

            final byte[] expected = bc.doFinal(input);
            final byte[] actual = botan.doFinal(input);

            Assert.assertArrayEquals("Decryption mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

    @Test
    public void testEncryptThenDecrypt() throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

        final Cipher cipher = Cipher.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

        final byte[] expected = withPadding ?
                HexUtils.decode("0397f4f6820b1f9386f14403be5ac16e50213bd473b4874b9bcbf5f318ee686b1d") :
                new byte[blockSize];

        cipher.init(ENCRYPT_MODE, key, iv);
        final byte[] cipherText = cipher.doFinal(expected);

        cipher.init(DECRYPT_MODE, key, iv);
        final byte[] plainText = cipher.doFinal(cipherText);

        Assert.assertArrayEquals(algorithm + " encrypt than decrypt mismatch", expected, plainText);
    }

    @Test
    public void testBotanPerformance() throws GeneralSecurityException {
        if (isSupportedByBouncyCastle) {
            final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
            final IvParameterSpec iv = new IvParameterSpec(new byte[blockSize]);

            final Cipher bc = Cipher.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            final Cipher botan = Cipher.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            bc.init(ENCRYPT_MODE, key, iv);
            botan.init(ENCRYPT_MODE, key, iv);

            final long startBc = System.nanoTime();
            for (int i = 0; i < 1_000; i++) {
                bc.update(new byte[1024]);
            }
            final byte[] expected = bc.doFinal();
            final long endBc = System.nanoTime();

            final long startBotan = System.nanoTime();
            for (int i = 0; i < 1_000; i++) {
                botan.update(new byte[1024]);
            }
            final byte[] actual = botan.doFinal();
            final long endBotan = System.nanoTime();

            double difference = (endBc - startBc) - (endBotan - startBotan);
            difference /= (endBc - startBc);
            difference *= 100;

            System.out.println("BC    : " + (endBc - startBc) + " ns");
            System.out.println("Botan : " + (endBotan - startBotan) + " ns");
            System.out.println(String.format(algorithm + " - Botan faster/slower than Bouncy castle by: %.2f ",
                    difference) + "%\n");

            Assert.assertArrayEquals("Cipher mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

}
