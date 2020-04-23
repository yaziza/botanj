/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.block;

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
                {"AES", 16, 16, true},
                {"AES", 16, 24, true},
                {"AES", 16, 32, true},
        });
    }

    private final String algorithm;
    private final int blockSize;
    private final int keySize;
    private final boolean isSupportedByBouncyCastle;

    public BotanBlockCipherTest(String algorithm, int blockSize, int keySize, boolean isSupportedByBouncyCastle) {
        this.algorithm = algorithm;
        this.blockSize = blockSize;
        this.keySize = keySize;
        this.isSupportedByBouncyCastle = isSupportedByBouncyCastle;
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
        final byte[] output = cipher.doFinal("some input".getBytes());

        Assert.assertEquals(algorithm + " block size in bytes", blockSize, cipher.getBlockSize());
        Assert.assertEquals(algorithm + " block size in bytes", blockSize, output.length);
    }

    @Test
    public void testEncryptAgainstBouncyCastle() throws GeneralSecurityException {
        if (isSupportedByBouncyCastle) {
            final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

            final Cipher bc = Cipher.getInstance(algorithm + "/ECB/Nopadding", BouncyCastleProvider.PROVIDER_NAME);
            final Cipher botan = Cipher.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            botan.init(ENCRYPT_MODE, key);
            bc.init(ENCRYPT_MODE, key);

            final byte[] expected = bc.doFinal(new byte[blockSize]);
            final byte[] actual = botan.doFinal(new byte[blockSize]);

            System.out.println(HexUtils.encodeToHexString(actual));
            System.out.println(HexUtils.encodeToHexString(expected));

            Assert.assertArrayEquals("Encryption mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

    @Test
    public void testDecryptAgainstBouncyCastle() throws GeneralSecurityException {
        if (isSupportedByBouncyCastle) {
            final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

            // Testing plain Botan AES against BC AES/ECB/Nopadding (testing only one block)
            final Cipher bc = Cipher.getInstance(algorithm + "/ECB/Nopadding", BouncyCastleProvider.PROVIDER_NAME);
            final Cipher botan = Cipher.getInstance(algorithm, BotanProvider.PROVIDER_NAME);

            botan.init(DECRYPT_MODE, key);
            bc.init(DECRYPT_MODE, key);

            final byte[] expected = bc.doFinal(HexUtils.decode("c774832283e6f92e4fb90d13d7ba9f7a"));
            final byte[] actual = botan.doFinal(HexUtils.decode("c774832283e6f92e4fb90d13d7ba9f7a"));

            Assert.assertArrayEquals("Decryption mismatch with Bouncy Castle provider for algorithm "
                    + algorithm, expected, actual);
        }
    }

}
