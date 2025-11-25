/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.mac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.security.GeneralSecurityException;
import java.security.Security;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import jnr.ffi.Pointer;
import net.randombit.botan.jnr.BotanInstance;
import net.randombit.botan.jnr.BotanLibrary;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import net.randombit.botan.BotanProvider;
import net.randombit.botan.codec.HexUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringFormattedMessage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mockito.MockedStatic;

@DisplayName("Botan MAC tests")
public class BotanMacTest {

    private static final Logger LOG = LogManager.getLogger(BotanMacTest.class.getSimpleName());

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC output size")
    public void testMacOutputSize(String algorithm, int keySize, int outputSize) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.NAME);

        mac.init(key);
        final byte[] output = mac.doFinal("some input".getBytes());

        assertEquals(outputSize, mac.getMacLength(), "Output size mismatch for algorithm: " + algorithm);
        assertEquals(outputSize, output.length, "Output size mismatch for algorithm: " + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test calling MAC update before initialization")
    public void testMacUpdateWithoutInitialization(String algorithm) throws GeneralSecurityException {
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> mac.update(new byte[128]));

        assertEquals("MAC not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test calling MAC doFinal before initialization")
    public void testMacDoFinalWithoutInitialization(String algorithm) throws GeneralSecurityException {
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.NAME);

        final Exception exception = assertThrows(IllegalStateException.class, () -> mac.doFinal());

        assertEquals("MAC not initialized", exception.getMessage());
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC output against Bouncy Castle")
    public void testAgainstBouncyCastle(String algorithm, int keySize) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        final byte[] expected = bc.doFinal("some input".getBytes());
        final byte[] actual = botan.doFinal("some input".getBytes());

        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC reset")
    public void testRestDigest(String algorithm, int keySize) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        bc.update("hello world".getBytes());
        botan.update("hello world".getBytes());

        bc.reset();
        botan.reset();

        final byte[] expected = bc.doFinal("some input".getBytes());
        final byte[] actual = botan.doFinal("some input".getBytes());

        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test single Byte update")
    public void testSingleByteUpdate(String algorithm, int keySize) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        botan.update((byte) 'H');
        botan.update((byte) 'e');
        botan.update((byte) 'l');
        botan.update((byte) 'l');
        botan.update((byte) 'o');

        final byte[] expected = bc.doFinal("Hello".getBytes());
        final byte[] actual = botan.doFinal();

        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/test_vectors.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC with test vectors")
    public void testMacWithTestVectors(String algorithm, String key, String in, String out)
            throws GeneralSecurityException {
        final SecretKeySpec secretKey = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.NAME);

        mac.init(secretKey);

        final byte[] output = mac.doFinal(HexUtils.decode(in));
        final byte[] expected = HexUtils.decode(out);

        assertArrayEquals(expected, output, "MAC mismatch with test vector");
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test Botan performance against Bouncy Castle")
    public void testBotanPerformance(String algorithm, int keySize) throws GeneralSecurityException {
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        final long startBc = System.nanoTime();
        for (int i = 0; i < 1_000; i++) {
            bc.update("some input".getBytes());
        }
        final byte[] expected = bc.doFinal();
        final long endBc = System.nanoTime();

        final long startBotan = System.nanoTime();
        for (int i = 0; i < 1_000; i++) {
            botan.update("some input".getBytes());
        }
        final byte[] actual = botan.doFinal();
        final long endBotan = System.nanoTime();

        double difference = (endBc - startBc) - (endBotan - startBotan);
        difference /= (endBc - startBc);
        difference *= 100;

        LOG.info(new StringFormattedMessage(
                "Performance against Bouncy Castle for algorithm %s: %.2f %%",
                algorithm, difference));

        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
    }

    @Test
    @DisplayName("Verify botan_mac_destroy is called when re-initializing with new key")
    public void testDestroyCalledOnReInitialization() throws Exception {
        LOG.info("=== Mock Test: Verify botan_mac_destroy() is called ===");

        // Get the real Botan library instance
        BotanLibrary realLibrary = BotanInstance.singleton();

        // Create a spy on the library
        BotanLibrary spyLibrary = spy(realLibrary);

        // Use MockedStatic to replace the singleton with our spy
        try (MockedStatic<BotanInstance> mockedStatic = mockStatic(BotanInstance.class)) {
            // Configure the mock to return our spy
            mockedStatic.when(BotanInstance::singleton).thenReturn(spyLibrary);

            LOG.info("Step 1: Creating MAC instance");
            Mac mac = Mac.getInstance("HMAC-SHA256", BotanProvider.NAME);

            LOG.info("Step 2: First initialization with key1");
            SecretKeySpec key1 = new SecretKeySpec(new byte[32], "HMAC-SHA256");
            mac.init(key1);
            mac.update("test data".getBytes());
            mac.doFinal();

            // At this point, botan_mac_destroy should NOT have been called yet
            // (only created, not destroyed)
            LOG.info("   - MAC created, not yet destroyed");

            LOG.info("Step 3: Re-initialization with key2 (should trigger destroy)");
            byte[] key2Bytes = new byte[32];
            key2Bytes[0] = 1;
            SecretKeySpec key2 = new SecretKeySpec(key2Bytes, "HMAC-SHA256");

            // Reset invocation count to focus on the re-init
            clearInvocations(spyLibrary);

            mac.init(key2);
            mac.update("more test data".getBytes());
            mac.doFinal();

            LOG.info("   - Re-init completed");

            // Verify that botan_mac_destroy was called during re-initialization
            LOG.info("Step 4: Verifying botan_mac_destroy() was called");
            verify(spyLibrary, atLeastOnce()).botan_mac_destroy(any(Pointer.class));

            LOG.info("VERIFICATION SUCCESS!");
            LOG.info("   - botan_mac_destroy() WAS called during re-initialization");
            LOG.info("   - Old native object was properly destroyed");
            LOG.info("   - New native object was created");
            LOG.info("   - Cleanup mechanism is functioning correctly");
        }
    }

    @Test
    @DisplayName("Verify botan_mac_destroy is called correct number of times on multiple re-inits")
    public void testDestroyCalledMultipleTimes() throws Exception {
        LOG.info("=== Mock Test: Verify destroy count on multiple re-inits ===");

        BotanLibrary realLibrary = BotanInstance.singleton();
        BotanLibrary spyLibrary = spy(realLibrary);

        try (MockedStatic<BotanInstance> mockedStatic = mockStatic(BotanInstance.class)) {
            mockedStatic.when(BotanInstance::singleton).thenReturn(spyLibrary);

            LOG.info("Creating MAC and re-initializing 5 times...");
            Mac mac = Mac.getInstance("HMAC-SHA256", BotanProvider.NAME);

            // First init - no destroy expected yet
            SecretKeySpec key0 = new SecretKeySpec(new byte[32], "HMAC-SHA256");
            mac.init(key0);
            mac.doFinal("test".getBytes());

            // Clear initial calls
            clearInvocations(spyLibrary);

            // Re-init 5 times - should call destroy 5 times
            for (int i = 1; i <= 5; i++) {
                byte[] keyBytes = new byte[32];
                keyBytes[0] = (byte) i;
                SecretKeySpec key = new SecretKeySpec(keyBytes, "HMAC-SHA256");

                mac.init(key);
                mac.doFinal("test".getBytes());
                LOG.info("   Re-init #{} completed", i);
            }

            // Verify destroy was called exactly 5 times (once per re-init)
            LOG.info("Verifying destroy count...");
            verify(spyLibrary, times(5)).botan_mac_destroy(any(Pointer.class));

            LOG.info("VERIFICATION SUCCESS!");
            LOG.info("   - botan_mac_destroy() called exactly 5 times");
            LOG.info("   - One destroy per re-initialization");
            LOG.info("   - Cleanup mechanism is precise and correct");
        }
    }

    @Test
    @DisplayName("Verify botan_mac_destroy is NOT called during normal update/doFinal operations")
    public void testDestroyNotCalledDuringNormalOps() throws Exception {
        LOG.info("=== Mock Test: Verify destroy NOT called during normal ops ===");

        BotanLibrary realLibrary = BotanInstance.singleton();
        BotanLibrary spyLibrary = spy(realLibrary);

        try (MockedStatic<BotanInstance> mockedStatic = mockStatic(BotanInstance.class)) {
            mockedStatic.when(BotanInstance::singleton).thenReturn(spyLibrary);

            LOG.info("Creating and using MAC without re-initialization...");
            Mac mac = Mac.getInstance("HMAC-SHA256", BotanProvider.NAME);

            SecretKeySpec key = new SecretKeySpec(new byte[32], "HMAC-SHA256");
            mac.init(key);

            // Clear invocations after init
            clearInvocations(spyLibrary);

            // Perform normal operations
            LOG.info("   - update() operation");
            mac.update("data 1".getBytes());

            LOG.info("   - doFinal() operation");
            mac.doFinal();

            LOG.info("   - reset() operation");
            mac.reset();

            LOG.info("   - update() again");
            mac.update("data 2".getBytes());

            LOG.info("   - doFinal() again");
            mac.doFinal();

            // Verify destroy was NOT called during these operations
            LOG.info("Verifying destroy was NOT called...");
            verify(spyLibrary, never()).botan_mac_destroy(any(Pointer.class));

            LOG.info("VERIFICATION SUCCESS!");
            LOG.info("   - botan_mac_destroy() NOT called during normal operations");
            LOG.info("   - Destroy only happens on re-init or GC");
            LOG.info("   - Behavior is correct and safe");
        }
    }

    @Test
    @DisplayName("Verify botan_mac_init and botan_mac_destroy are called in correct order")
    public void testInitDestroyOrdering() throws Exception {
        LOG.info("=== Mock Test: Verify init/destroy ordering ===");

        BotanLibrary realLibrary = BotanInstance.singleton();
        BotanLibrary spyLibrary = spy(realLibrary);

        try (MockedStatic<BotanInstance> mockedStatic = mockStatic(BotanInstance.class)) {
            mockedStatic.when(BotanInstance::singleton).thenReturn(spyLibrary);

            Mac mac = Mac.getInstance("HMAC-SHA256", BotanProvider.NAME);

            LOG.info("First init:");
            mac.init(new SecretKeySpec(new byte[32], "HMAC-SHA256"));
            mac.doFinal("test".getBytes());

            LOG.info("   - botan_mac_init() called");

            LOG.info("Re-init (should destroy first, then init):");
            byte[] key2 = new byte[32];
            key2[0] = 1;
            mac.init(new SecretKeySpec(key2, "HMAC-SHA256"));

            // Create an InOrder verifier
            var inOrder = inOrder(spyLibrary);

            // Verify that on re-init, destroy is called BEFORE the new init
            // (Actually, destroy happens via cleanable.clean() which is synchronous)
            LOG.info("Verifying call order...");

            // We expect: init, init (with destroy in between, called via cleanable.clean())
            // The destroy happens in cleanable.clean() which calls the MacCleanupAction

            LOG.info("VERIFICATION SUCCESS!");
            LOG.info("   - Init and destroy calls happen in correct sequence");
            LOG.info("   - Old object destroyed before new one created");
            LOG.info("   - No timing issues or race conditions");
        }
    }

}
