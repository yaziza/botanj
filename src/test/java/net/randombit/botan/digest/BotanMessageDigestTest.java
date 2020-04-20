/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.digest;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import net.randombit.botan.BotanProvider;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class BotanMessageDigestTest {

    @Parameterized.Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {"sha1", 20},
                {"sha-224", 28}, {"sha-256", 32}, {"sha-384", 48}, {"sha-512", 64},
                {"sha3-224", 28}, {"sha3-256", 32}, {"sha3-384", 48}, {"sha3-512", 64},
                {"keccak-224", 28}, {"keccak-256", 32}, {"keccak-384", 48}, {"keccak-512", 64},
                {"blake2b-160", 20}, {"blake2b-256", 32}, {"blake2b-384", 48}, {"blake2b-512", 64},
                {"ripemd-160", 20},
        });
    }

    private final String algorithm;
    private final int size;

    public BotanMessageDigestTest(String algorithm, int size) {
        this.algorithm = algorithm;
        this.size = size;
    }

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new BotanProvider());
    }

    @Test
    public void testDigestOutputSize() throws GeneralSecurityException {
        final MessageDigest digest = MessageDigest.getInstance(algorithm, BotanProvider.PROVIDER_NAME);
        final byte[] output = digest.digest("Some input".getBytes());

        Assert.assertEquals(algorithm + " output size in bytes", size, digest.getDigestLength());
        Assert.assertEquals(algorithm + " output size in bytes", size, output.length);
    }

}
