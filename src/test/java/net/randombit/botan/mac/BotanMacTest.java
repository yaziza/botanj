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
        LOG.info("=== Test: MAC output size for {} ===", algorithm);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.NAME);

        LOG.info("Key size: {} bytes", keySize);
        LOG.info("Expected output size: {} bytes", outputSize);
        mac.init(key);
        final byte[] output = mac.doFinal("some input".getBytes());
        LOG.info("Actual output size: {} bytes", output.length);

        assertEquals(outputSize, mac.getMacLength(), "Output size mismatch for algorithm: " + algorithm);
        assertEquals(outputSize, output.length, "Output size mismatch for algorithm: " + algorithm);
        LOG.info("SUCCESS: Output size matches for {}", algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test calling MAC update before initialization")
    public void testMacUpdateWithoutInitialization(String algorithm) throws GeneralSecurityException {
        LOG.info("=== Test: MAC update without initialization for {} ===", algorithm);
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.NAME);

        LOG.info("Attempting update without initialization...");
        final Exception exception = assertThrows(IllegalStateException.class, () -> mac.update(new byte[128]));

        assertEquals("MAC not initialized", exception.getMessage());
        LOG.info("SUCCESS: Properly rejected uninitialized update for {}", algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test calling MAC doFinal before initialization")
    public void testMacDoFinalWithoutInitialization(String algorithm) throws GeneralSecurityException {
        LOG.info("=== Test: MAC doFinal without initialization for {} ===", algorithm);
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.NAME);

        LOG.info("Attempting doFinal without initialization...");
        final Exception exception = assertThrows(IllegalStateException.class, () -> mac.doFinal());

        assertEquals("MAC not initialized", exception.getMessage());
        LOG.info("SUCCESS: Properly rejected uninitialized doFinal for {}", algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC output against Bouncy Castle")
    public void testAgainstBouncyCastle(String algorithm, int keySize) throws GeneralSecurityException {
        LOG.info("=== Test: MAC {} against Bouncy Castle ===", algorithm);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        LOG.info("Initializing both MACs with {} byte key", keySize);
        bc.init(key);
        botan.init(key);

        final byte[] expected = bc.doFinal("some input".getBytes());
        final byte[] actual = botan.doFinal("some input".getBytes());

        LOG.info("Bouncy Castle output: {} bytes", expected.length);
        LOG.info("Botan output: {} bytes", actual.length);
        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
        LOG.info("SUCCESS: {} matches Bouncy Castle", algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC reset (Only for Botan)")
    public void testRestDigest(String algorithm, int keySize) throws GeneralSecurityException {
        LOG.info("=== Test: MAC reset for {} ===", algorithm);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        LOG.info("Updating Botan with 'hello world', then resetting...");
        botan.update("hello world".getBytes());
        botan.reset();

        LOG.info("Computing MAC for 'some input' on both providers");
        final byte[] expected = bc.doFinal("some input".getBytes());
        final byte[] actual = botan.doFinal("some input".getBytes());

        LOG.info("Expected (BC): {} bytes", expected.length);
        LOG.info("Actual (Botan after reset): {} bytes", actual.length);
        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
        LOG.info("SUCCESS: Reset works correctly for {}", algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC reset (BC also reset)")
    public void testBothRestDigest(String algorithm, int keySize) throws GeneralSecurityException {
        LOG.info("=== Test: MAC reset (both providers) for {} ===", algorithm);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        LOG.info("Updating both with 'hello world'");
        bc.update("hello world".getBytes());
        botan.update("hello world".getBytes());

        LOG.info("Resetting both MACs");
        bc.reset();
        botan.reset();

        LOG.info("Computing MAC for 'some input' on both providers");
        final byte[] expected = bc.doFinal("some input".getBytes());
        final byte[] actual = botan.doFinal("some input".getBytes());

        LOG.info("Expected (BC): {} bytes", expected.length);
        LOG.info("Actual (Botan): {} bytes", actual.length);
        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
        LOG.info("SUCCESS: Both resets work correctly for {}", algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/mac.csv", numLinesToSkip = 1)
    @DisplayName("Test single Byte update")
    public void testSingleByteUpdate(String algorithm, int keySize) throws GeneralSecurityException {
        LOG.info("=== Test: Single byte update for {} ===", algorithm);
        final SecretKeySpec key = new SecretKeySpec(new byte[keySize], algorithm);

        final Mac bc = Mac.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        final Mac botan = Mac.getInstance(algorithm, BotanProvider.NAME);

        bc.init(key);
        botan.init(key);

        LOG.info("Updating Botan MAC byte-by-byte: 'H', 'e', 'l', 'l', 'o'");
        botan.update((byte) 'H');
        botan.update((byte) 'e');
        botan.update((byte) 'l');
        botan.update((byte) 'l');
        botan.update((byte) 'o');

        LOG.info("Updating BC MAC with full string: 'Hello'");
        final byte[] expected = bc.doFinal("Hello".getBytes());
        final byte[] actual = botan.doFinal();

        LOG.info("Expected (BC): {} bytes", expected.length);
        LOG.info("Actual (Botan byte-by-byte): {} bytes", actual.length);
        assertArrayEquals(expected, actual, "MAC mismatch with Bouncy Castle provider for algorithm: "
                + algorithm);
        LOG.info("SUCCESS: Single byte updates work correctly for {}", algorithm);
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/mac/test_vectors.csv", numLinesToSkip = 1)
    @DisplayName("Test MAC with test vectors")
    public void testMacWithTestVectors(String algorithm, String key, String in, String out)
            throws GeneralSecurityException {
        LOG.info("=== Test: {} with test vector ===", algorithm);
        final SecretKeySpec secretKey = new SecretKeySpec(HexUtils.decode(key), algorithm);
        final Mac mac = Mac.getInstance(algorithm, BotanProvider.NAME);

        LOG.info("Key: {} bytes", HexUtils.decode(key).length);
        LOG.info("Input: {} bytes", HexUtils.decode(in).length);
        mac.init(secretKey);

        final byte[] output = mac.doFinal(HexUtils.decode(in));
        final byte[] expected = HexUtils.decode(out);

        LOG.info("Expected output: {} bytes", expected.length);
        LOG.info("Actual output: {} bytes", output.length);
        assertArrayEquals(expected, output, "MAC mismatch with test vector");
        LOG.info("SUCCESS: {} matches test vector", algorithm);
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

            LOG.info("Step 2: First initialization with first Key");
            SecretKeySpec firstKey = new SecretKeySpec(new byte[32], "HMAC-SHA256");

            mac.init(firstKey);
            mac.update("test data".getBytes());
            mac.doFinal();

            // At this point, botan_mac_destroy should NOT have been called yet
            // (only created, not destroyed)
            LOG.info("   - MAC created, not yet destroyed");

            LOG.info("Step 3: Re-initialization with second Key (should trigger destroy)");
            byte[] secondKeyBytes = new byte[32];
            secondKeyBytes[0] = 1;
            SecretKeySpec secondKey = new SecretKeySpec(secondKeyBytes, "HMAC-SHA256");

            verify(spyLibrary, never()).botan_mac_destroy(any(Pointer.class));

            // Reset invocation count to focus on the re-init
            clearInvocations(spyLibrary);

            mac.init(secondKey);
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
            SecretKeySpec firstKey = new SecretKeySpec(new byte[32], "HMAC-SHA256");
            mac.init(firstKey);
            mac.doFinal("test".getBytes());

            verify(spyLibrary, never()).botan_mac_destroy(any(Pointer.class));

            // Clear initial calls
            clearInvocations(spyLibrary);

            // Re-init 5 times - should call destroy 5 times
            for (int i = 1; i <= 5; i++) {
                byte[] roundKeyBytes = new byte[32];
                roundKeyBytes[0] = (byte) i;
                SecretKeySpec roundKey = new SecretKeySpec(roundKeyBytes, "HMAC-SHA256");

                mac.init(roundKey);
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
    @DisplayName("Verify clone throws CloneNotSupportedException")
    public void testCloneThrowsException() throws Exception {
        LOG.info("=== Test: Verify MAC clone throws CloneNotSupportedException ===");
        Mac mac = Mac.getInstance("HmacSHA256", BotanProvider.NAME);
        SecretKeySpec key = new SecretKeySpec(new byte[32], "AES");
        mac.init(key);
        mac.update("test".getBytes());

        LOG.info("Attempting to clone MAC...");
        assertThrows(CloneNotSupportedException.class, () -> {
            mac.clone();
        }, "clone() should throw CloneNotSupportedException");
        LOG.info("SUCCESS: Clone properly threw CloneNotSupportedException");
    }

}
