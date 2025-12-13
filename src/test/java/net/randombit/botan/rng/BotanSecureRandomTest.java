/*
 * (C) 2025 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.rng;

import net.randombit.botan.BotanProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for Botan SecureRandom implementations.
 */
@DisplayName("Botan SecureRandom tests")
public class BotanSecureRandomTest {

    private static final Logger LOG = LogManager.getLogger(BotanSecureRandomTest.class);

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
        LOG.info("=== Botan SecureRandom Test Suite ===");
    }

    @Test
    @DisplayName("Test System RNG initialization")
    void testSystemRngInit() throws Exception {
        LOG.info("=== Test: System RNG initialization ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");
        assertNotNull(rng, "System RNG should be initialized");
        assertEquals("Botan", rng.getProvider().getName());
        LOG.info("SUCCESS: System RNG initialized with provider: {}", rng.getProvider().getName());
    }

    @Test
    @DisplayName("Test System RNG via alias")
    void testSystemRngAlias() throws Exception {
        LOG.info("=== Test: System RNG via alias ===");
        SecureRandom rng = SecureRandom.getInstance("BotanSystem", "Botan");
        assertNotNull(rng, "System RNG should be accessible via alias");
        LOG.info("SUCCESS: System RNG accessible via alias 'BotanSystem'");
    }

    @Test
    @DisplayName("Test User RNG initialization")
    void testUserRngInit() throws Exception {
        LOG.info("=== Test: User RNG initialization ===");
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");
        assertNotNull(rng, "User RNG should be initialized");
        assertEquals("Botan", rng.getProvider().getName());
        LOG.info("SUCCESS: User RNG initialized with provider: {}", rng.getProvider().getName());
    }

    @Test
    @DisplayName("Test User Threadsafe RNG initialization")
    void testUserThreadsafeRngInit() throws Exception {
        LOG.info("=== Test: User Threadsafe RNG initialization ===");
        SecureRandom rng = SecureRandom.getInstance("BotanUserThreadsafe", "Botan");
        assertNotNull(rng, "User Threadsafe RNG should be initialized");
        assertEquals("Botan", rng.getProvider().getName());
        LOG.info("SUCCESS: User Threadsafe RNG initialized with provider: {}", rng.getProvider().getName());
    }

    @Test
    @DisplayName("Test generating random bytes")
    void testGenerateRandomBytes() throws Exception {
        LOG.info("=== Test: Generate random bytes ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        byte[] bytes = new byte[32];
        rng.nextBytes(bytes);

        // Check that not all bytes are zero (extremely unlikely for random data)
        boolean hasNonZero = false;
        for (byte b : bytes) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Random bytes should contain non-zero values");
        LOG.info("SUCCESS: Generated 32 random bytes with non-zero values");
    }

    @Test
    @DisplayName("Test generating different random values")
    void testRandomnessUniqueness() throws Exception {
        LOG.info("=== Test: Randomness uniqueness ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        byte[] bytes1 = new byte[32];
        byte[] bytes2 = new byte[32];

        rng.nextBytes(bytes1);
        rng.nextBytes(bytes2);

        assertFalse(Arrays.equals(bytes1, bytes2),
                "Consecutive random byte arrays should be different");
        LOG.info("SUCCESS: Consecutive random byte arrays are different");
    }

    @Test
    @DisplayName("Test empty byte array")
    void testEmptyByteArray() throws Exception {
        LOG.info("=== Test: Empty byte array ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        byte[] empty = new byte[0];
        assertDoesNotThrow(() -> rng.nextBytes(empty),
                "nextBytes should handle empty array");
        LOG.info("SUCCESS: Empty byte array handled correctly");
    }

    @Test
    @DisplayName("Test null byte array")
    void testNullByteArray() throws Exception {
        LOG.info("=== Test: Null byte array ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        assertThrows(NullPointerException.class, () -> rng.nextBytes(null),
                "nextBytes should throw NullPointerException for null array");
        LOG.info("SUCCESS: NullPointerException thrown for null array");
    }

    @Test
    @DisplayName("Test generateSeed")
    void testGenerateSeed() throws Exception {
        LOG.info("=== Test: Generate seed ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        byte[] seed = rng.generateSeed(32);
        assertNotNull(seed, "Generated seed should not be null");
        assertEquals(32, seed.length, "Generated seed should have requested length");

        // Check randomness
        boolean hasNonZero = false;
        for (byte b : seed) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Generated seed should contain non-zero values");
        LOG.info("SUCCESS: Generated 32-byte seed with non-zero values");
    }

    @Test
    @DisplayName("Test generateSeed with zero length")
    void testGenerateSeedZero() throws Exception {
        LOG.info("=== Test: Generate seed with zero length ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        byte[] seed = rng.generateSeed(0);
        assertNotNull(seed, "Generated seed should not be null");
        assertEquals(0, seed.length, "Generated seed should be empty");
        LOG.info("SUCCESS: Generated empty seed (length=0)");
    }

    @Test
    @DisplayName("Test generateSeed with negative length")
    void testGenerateSeedNegative() throws Exception {
        LOG.info("=== Test: Generate seed with negative length ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        assertThrows(IllegalArgumentException.class,
                () -> rng.generateSeed(-1),
                "generateSeed should throw for negative length");
        LOG.info("SUCCESS: IllegalArgumentException thrown for negative length");
    }

    @Test
    @DisplayName("Test setSeed with custom entropy")
    void testSetSeed() throws Exception {
        LOG.info("=== Test: Set seed with custom entropy ===");
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");

        byte[] customSeed = new byte[32];
        Arrays.fill(customSeed, (byte) 0x42);

        assertDoesNotThrow(() -> rng.setSeed(customSeed),
                "setSeed should accept custom entropy");

        // Generate some random bytes to ensure it still works
        byte[] output = new byte[16];
        rng.nextBytes(output);
        assertNotNull(output, "RNG should work after setSeed");
        LOG.info("SUCCESS: Custom seed accepted and RNG works after setSeed");
    }

    @Test
    @DisplayName("Test setSeed with empty array")
    void testSetSeedEmpty() throws Exception {
        LOG.info("=== Test: Set seed with empty array ===");
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");

        assertDoesNotThrow(() -> rng.setSeed(new byte[0]),
                "setSeed should handle empty array");
        LOG.info("SUCCESS: Empty array handled correctly");
    }

    @Test
    @DisplayName("Test setSeed with null")
    void testSetSeedNull() throws Exception {
        LOG.info("=== Test: Set seed with null ===");
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");

        assertThrows(NullPointerException.class, () -> rng.setSeed(null),
                "setSeed should throw NullPointerException for null");
        LOG.info("SUCCESS: NullPointerException thrown for null seed");
    }

    @Test
    @DisplayName("Test large random byte generation")
    void testLargeRandomGeneration() throws Exception {
        LOG.info("=== Test: Large random byte generation (10 KB) ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        int size = 10 * 1024; // 10 KB
        byte[] largeBytes = new byte[size];

        long startTime = System.nanoTime();
        rng.nextBytes(largeBytes);
        long duration = System.nanoTime() - startTime;

        // Verify non-zero content
        boolean hasNonZero = false;
        for (int i = 0; i < Math.min(100, size); i++) {
            if (largeBytes[i] != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Large random output should contain non-zero values");

        // Performance check - should be reasonably fast (less than 100ms for 10KB)
        long durationMs = duration / 1_000_000;
        LOG.info("Generated 10 KB in {} ms", durationMs);
        assertTrue(duration < 100_000_000L,
                "Generating 10KB should be fast (took " + durationMs + "ms)");
        LOG.info("SUCCESS: Large random generation completed in {} ms", durationMs);
    }

    @Test
    @DisplayName("Test statistical distribution (basic check)")
    void testBasicStatistics() throws Exception {
        LOG.info("=== Test: Statistical distribution (10,000 bytes) ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        int sampleSize = 10000;
        byte[] bytes = new byte[sampleSize];
        rng.nextBytes(bytes);

        // Count zeros and ones in bits
        int zeros = 0;
        int ones = 0;

        for (byte b : bytes) {
            for (int i = 0; i < 8; i++) {
                if ((b & (1 << i)) == 0) {
                    zeros++;
                } else {
                    ones++;
                }
            }
        }

        int totalBits = sampleSize * 8;

        // Expect roughly 50/50 distribution (allow 10% deviation)
        double zeroRatio = (double) zeros / totalBits;
        LOG.info("Bit distribution: {} zeros ({}%), {} ones ({}%)",
                zeros, String.format("%.2f", zeroRatio * 100),
                ones, String.format("%.2f", (1 - zeroRatio) * 100));
        assertTrue(zeroRatio > 0.40 && zeroRatio < 0.60,
                "Zero bits should be roughly 50% (got " + (zeroRatio * 100) + "%)");
        LOG.info("SUCCESS: Bit distribution is within acceptable range");
    }

    @Test
    @DisplayName("Test User RNG vs System RNG performance comparison")
    void testPerformanceComparison() throws Exception {
        LOG.info("=== Test: Performance comparison (1 MB generation) ===");
        SecureRandom systemRng = SecureRandom.getInstance("Botan", "Botan");
        SecureRandom userRng = SecureRandom.getInstance("BotanUser", "Botan");

        int size = 1024 * 1024; // 1 MB
        byte[] buffer = new byte[size];

        // Warm up
        LOG.info("Warming up RNGs...");
        systemRng.nextBytes(new byte[1024]);
        userRng.nextBytes(new byte[1024]);

        // Test System RNG
        LOG.info("Testing System RNG...");
        long systemStart = System.nanoTime();
        systemRng.nextBytes(buffer);
        long systemDuration = System.nanoTime() - systemStart;
        long systemMs = systemDuration / 1_000_000;

        // Test User RNG
        LOG.info("Testing User RNG...");
        long userStart = System.nanoTime();
        userRng.nextBytes(buffer);
        long userDuration = System.nanoTime() - userStart;
        long userMs = userDuration / 1_000_000;

        // User RNG should generally be faster than System RNG
        // (But we don't enforce this strictly as it depends on the system)
        LOG.info("System RNG: {} ms", systemMs);
        LOG.info("User RNG: {} ms", userMs);
        System.out.println("System RNG: " + systemMs + "ms");
        System.out.println("User RNG: " + userMs + "ms");

        double speedup = (double) systemDuration / userDuration;
        LOG.info("User RNG is {:.2f}x {} than System RNG",
                Math.abs(speedup),
                speedup > 1 ? "faster" : "slower");

        assertTrue(systemDuration > 0 && userDuration > 0,
                "Both RNGs should complete successfully");
        LOG.info("SUCCESS: Performance comparison completed");
    }

    @Test
    @DisplayName("Test multiple RNG instances are independent")
    void testMultipleInstances() throws Exception {
        LOG.info("=== Test: Multiple RNG instances independence ===");
        SecureRandom rng1 = SecureRandom.getInstance("Botan", "Botan");
        SecureRandom rng2 = SecureRandom.getInstance("Botan", "Botan");

        byte[] bytes1 = new byte[32];
        byte[] bytes2 = new byte[32];

        rng1.nextBytes(bytes1);
        rng2.nextBytes(bytes2);

        // Different instances should produce different random values
        assertFalse(Arrays.equals(bytes1, bytes2),
                "Different RNG instances should produce different output");
        LOG.info("SUCCESS: Different RNG instances produce different output");
    }

    @Test
    @DisplayName("Test all RNG types produce unique output")
    void testAllRngTypes() throws Exception {
        LOG.info("=== Test: All RNG types produce unique output ===");
        String[] rngTypes = {"Botan", "BotanUser", "BotanUserThreadsafe"};
        Set<String> outputs = new HashSet<>();

        for (String type : rngTypes) {
            SecureRandom rng = SecureRandom.getInstance(type, "Botan");
            byte[] bytes = new byte[32];
            rng.nextBytes(bytes);

            String output = Arrays.toString(bytes);
            outputs.add(output);
            LOG.info("Generated output from RNG type: {}", type);
        }

        assertEquals(rngTypes.length, outputs.size(),
                "All RNG types should produce unique output");
        LOG.info("SUCCESS: All {} RNG types produced unique output", rngTypes.length);
    }

    @Test
    @DisplayName("Test reseed with 256 bits")
    void testReseed256() throws Exception {
        LOG.info("=== Test: Reseed with 256 bits ===");
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");

        // Use reflection to access the protected reseed method
        java.lang.reflect.Method reseedMethod = BotanSecureRandom.class.getDeclaredMethod("reseed", long.class);
        reseedMethod.setAccessible(true);

        // Reseed should not throw
        assertDoesNotThrow(() -> {
            try {
                reseedMethod.invoke(rng.getProvider().getService("SecureRandom", "BotanUser").newInstance(null), 256L);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, "Reseed with 256 bits should succeed");

        // Generate random bytes after creating a new instance
        byte[] bytes = new byte[32];
        rng.nextBytes(bytes);

        // Verify output is non-zero
        boolean hasNonZero = false;
        for (byte b : bytes) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Random bytes should contain non-zero values");
        LOG.info("SUCCESS: Reseed with 256 bits completed, RNG works correctly");
    }

    @Test
    @DisplayName("Test reseed with 384 bits")
    void testReseed384() throws Exception {
        LOG.info("=== Test: Reseed with 384 bits ===");
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");

        // Use reflection to access the protected reseed method
        java.lang.reflect.Method reseedMethod = BotanSecureRandom.class.getDeclaredMethod("reseed", long.class);
        reseedMethod.setAccessible(true);

        // Reseed should not throw
        assertDoesNotThrow(() -> {
            try {
                reseedMethod.invoke(rng.getProvider().getService("SecureRandom", "BotanUser").newInstance(null), 384L);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, "Reseed with 384 bits should succeed");

        // Generate random bytes
        byte[] bytes = new byte[32];
        rng.nextBytes(bytes);

        boolean hasNonZero = false;
        for (byte b : bytes) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Random bytes should contain non-zero values");
        LOG.info("SUCCESS: Reseed with 384 bits completed, RNG works correctly");
    }

    @Test
    @DisplayName("Test nextInt method")
    void testNextInt() throws Exception {
        LOG.info("=== Test: nextInt method ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        // Test basic nextInt
        int value = rng.nextInt();
        assertNotNull(value); // Just ensure it doesn't crash
        LOG.info("Generated random int: {}", value);

        // Test nextInt with bound
        int boundedValue = rng.nextInt(100);
        assertTrue(boundedValue >= 0 && boundedValue < 100,
                "nextInt(100) should be in range [0, 100)");
        LOG.info("Generated bounded int (0-99): {}", boundedValue);
        LOG.info("SUCCESS: nextInt methods work correctly");
    }

    @Test
    @DisplayName("Test nextLong method")
    void testNextLong() throws Exception {
        LOG.info("=== Test: nextLong method ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        long value = rng.nextLong();
        assertNotNull(value); // Just ensure it doesn't crash
        LOG.info("Generated random long: {}", value);
        LOG.info("SUCCESS: nextLong method works correctly");
    }

    @Test
    @DisplayName("Test nextBoolean method")
    void testNextBoolean() throws Exception {
        LOG.info("=== Test: nextBoolean method ===");
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        // Generate many booleans and check distribution
        int trueCount = 0;
        int iterations = 1000;

        for (int i = 0; i < iterations; i++) {
            if (rng.nextBoolean()) {
                trueCount++;
            }
        }

        // Should be roughly 50/50 (allow 20% deviation)
        double trueRatio = (double) trueCount / iterations;
        LOG.info("Generated {} booleans: {} true ({}%), {} false ({}%)",
                iterations, trueCount, String.format("%.2f", trueRatio * 100),
                (iterations - trueCount), String.format("%.2f", (1 - trueRatio) * 100));
        assertTrue(trueRatio > 0.30 && trueRatio < 0.70,
                "nextBoolean should produce roughly 50% true values (got " + (trueRatio * 100) + "%)");
        LOG.info("SUCCESS: nextBoolean distribution is within acceptable range");
    }

    @Test
    @DisplayName("Test System RNG has ThreadSafe property set to true")
    void testSystemRngThreadSafeProperty() throws Exception {
        LOG.info("=== Test: System RNG ThreadSafe property ===");
        BotanProvider provider = new BotanProvider();

        String threadSafeProperty = provider.getProperty("SecureRandom.Botan ThreadSafe");

        assertNotNull(threadSafeProperty, "ThreadSafe property should be set for Botan (System) RNG");
        assertEquals("true", threadSafeProperty,
                "System RNG should be marked as thread-safe");
        LOG.info("SUCCESS: System RNG ThreadSafe property = {}", threadSafeProperty);
    }

    @Test
    @DisplayName("Test User RNG has ThreadSafe property set to false")
    void testUserRngThreadSafeProperty() throws Exception {
        LOG.info("=== Test: User RNG ThreadSafe property ===");
        BotanProvider provider = new BotanProvider();

        String threadSafeProperty = provider.getProperty("SecureRandom.BotanUser ThreadSafe");

        assertNotNull(threadSafeProperty, "ThreadSafe property should be set for BotanUser RNG");
        assertEquals("false", threadSafeProperty,
                "User RNG should be marked as NOT thread-safe");
        LOG.info("SUCCESS: User RNG ThreadSafe property = {}", threadSafeProperty);
    }

    @Test
    @DisplayName("Test UserThreadsafe RNG has ThreadSafe property set to true")
    void testUserThreadsafeRngThreadSafeProperty() throws Exception {
        LOG.info("=== Test: UserThreadsafe RNG ThreadSafe property ===");
        BotanProvider provider = new BotanProvider();

        String threadSafeProperty = provider.getProperty("SecureRandom.BotanUserThreadsafe ThreadSafe");

        assertNotNull(threadSafeProperty, "ThreadSafe property should be set for BotanUserThreadsafe RNG");
        assertEquals("true", threadSafeProperty,
                "UserThreadsafe RNG should be marked as thread-safe");
        LOG.info("SUCCESS: UserThreadsafe RNG ThreadSafe property = {}", threadSafeProperty);
    }

    @Test
    @DisplayName("Test concurrent access to threadsafe RNG")
    void testThreadsafeRng() throws Exception {
        LOG.info("=== Test: Concurrent access to threadsafe RNG ===");
        SecureRandom rng = SecureRandom.getInstance("BotanUserThreadsafe", "Botan");

        int numThreads = 10;
        int bytesPerThread = 1024;
        LOG.info("Testing with {} threads, {} bytes per thread", numThreads, bytesPerThread);

        Thread[] threads = new Thread[numThreads];
        byte[][] results = new byte[numThreads][bytesPerThread];

        long startTime = System.nanoTime();
        for (int i = 0; i < numThreads; i++) {
            final int index = i;
            threads[i] = new Thread(() -> rng.nextBytes(results[index]));
            threads[i].start();
        }

        // Wait for all threads
        for (Thread thread : threads) {
            thread.join();
        }
        long duration = System.nanoTime() - startTime;

        // Verify all outputs are different
        Set<String> uniqueOutputs = new HashSet<>();
        for (byte[] result : results) {
            uniqueOutputs.add(Arrays.toString(result));
        }

        LOG.info("All {} threads completed in {} ms", numThreads, duration / 1_000_000);
        LOG.info("Generated {} unique outputs", uniqueOutputs.size());

        assertEquals(numThreads, uniqueOutputs.size(),
                "Threadsafe RNG should produce unique output for each thread");
        LOG.info("SUCCESS: Threadsafe RNG produced unique output for all threads");
    }
}
