/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.rng;

import net.randombit.botan.BotanProvider;
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

    @BeforeAll
    public static void setUp() {
        Security.addProvider(new BotanProvider());
    }

    @Test
    @DisplayName("Test System RNG initialization")
    void testSystemRngInit() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");
        assertNotNull(rng, "System RNG should be initialized");
        assertEquals("Botan", rng.getProvider().getName());
    }

    @Test
    @DisplayName("Test System RNG via alias")
    void testSystemRngAlias() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("BotanSystem", "Botan");
        assertNotNull(rng, "System RNG should be accessible via alias");
    }

    @Test
    @DisplayName("Test User RNG initialization")
    void testUserRngInit() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");
        assertNotNull(rng, "User RNG should be initialized");
        assertEquals("Botan", rng.getProvider().getName());
    }

    @Test
    @DisplayName("Test User Threadsafe RNG initialization")
    void testUserThreadsafeRngInit() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("BotanUserThreadsafe", "Botan");
        assertNotNull(rng, "User Threadsafe RNG should be initialized");
        assertEquals("Botan", rng.getProvider().getName());
    }

    @Test
    @DisplayName("Test generating random bytes")
    void testGenerateRandomBytes() throws Exception {
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
    }

    @Test
    @DisplayName("Test generating different random values")
    void testRandomnessUniqueness() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        byte[] bytes1 = new byte[32];
        byte[] bytes2 = new byte[32];

        rng.nextBytes(bytes1);
        rng.nextBytes(bytes2);

        assertFalse(Arrays.equals(bytes1, bytes2),
                "Consecutive random byte arrays should be different");
    }

    @Test
    @DisplayName("Test empty byte array")
    void testEmptyByteArray() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        byte[] empty = new byte[0];
        assertDoesNotThrow(() -> rng.nextBytes(empty),
                "nextBytes should handle empty array");
    }

    @Test
    @DisplayName("Test null byte array")
    void testNullByteArray() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        assertThrows(NullPointerException.class, () -> rng.nextBytes(null),
                "nextBytes should throw NullPointerException for null array");
    }

    @Test
    @DisplayName("Test generateSeed")
    void testGenerateSeed() throws Exception {
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
    }

    @Test
    @DisplayName("Test generateSeed with zero length")
    void testGenerateSeedZero() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        byte[] seed = rng.generateSeed(0);
        assertNotNull(seed, "Generated seed should not be null");
        assertEquals(0, seed.length, "Generated seed should be empty");
    }

    @Test
    @DisplayName("Test generateSeed with negative length")
    void testGenerateSeedNegative() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        assertThrows(IllegalArgumentException.class,
                () -> rng.generateSeed(-1),
                "generateSeed should throw for negative length");
    }

    @Test
    @DisplayName("Test setSeed with custom entropy")
    void testSetSeed() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");

        byte[] customSeed = new byte[32];
        Arrays.fill(customSeed, (byte) 0x42);

        assertDoesNotThrow(() -> rng.setSeed(customSeed),
                "setSeed should accept custom entropy");

        // Generate some random bytes to ensure it still works
        byte[] output = new byte[16];
        rng.nextBytes(output);
        assertNotNull(output, "RNG should work after setSeed");
    }

    @Test
    @DisplayName("Test setSeed with empty array")
    void testSetSeedEmpty() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");

        assertDoesNotThrow(() -> rng.setSeed(new byte[0]),
                "setSeed should handle empty array");
    }

    @Test
    @DisplayName("Test setSeed with null")
    void testSetSeedNull() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("BotanUser", "Botan");

        assertThrows(NullPointerException.class, () -> rng.setSeed(null),
                "setSeed should throw NullPointerException for null");
    }

    @Test
    @DisplayName("Test large random byte generation")
    void testLargeRandomGeneration() throws Exception {
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
        assertTrue(duration < 100_000_000L,
                "Generating 10KB should be fast (took " + duration / 1_000_000 + "ms)");
    }

    @Test
    @DisplayName("Test statistical distribution (basic check)")
    void testBasicStatistics() throws Exception {
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
        assertTrue(zeroRatio > 0.40 && zeroRatio < 0.60,
                "Zero bits should be roughly 50% (got " + (zeroRatio * 100) + "%)");
    }

    @Test
    @DisplayName("Test User RNG vs System RNG performance comparison")
    void testPerformanceComparison() throws Exception {
        SecureRandom systemRng = SecureRandom.getInstance("Botan", "Botan");
        SecureRandom userRng = SecureRandom.getInstance("BotanUser", "Botan");

        int size = 1024 * 1024; // 1 MB
        byte[] buffer = new byte[size];

        // Warm up
        systemRng.nextBytes(new byte[1024]);
        userRng.nextBytes(new byte[1024]);

        // Test System RNG
        long systemStart = System.nanoTime();
        systemRng.nextBytes(buffer);
        long systemDuration = System.nanoTime() - systemStart;

        // Test User RNG
        long userStart = System.nanoTime();
        userRng.nextBytes(buffer);
        long userDuration = System.nanoTime() - userStart;

        // User RNG should generally be faster than System RNG
        // (But we don't enforce this strictly as it depends on the system)
        System.out.println("System RNG: " + systemDuration / 1_000_000 + "ms");
        System.out.println("User RNG: " + userDuration / 1_000_000 + "ms");

        assertTrue(systemDuration > 0 && userDuration > 0,
                "Both RNGs should complete successfully");
    }

    @Test
    @DisplayName("Test multiple RNG instances are independent")
    void testMultipleInstances() throws Exception {
        SecureRandom rng1 = SecureRandom.getInstance("Botan", "Botan");
        SecureRandom rng2 = SecureRandom.getInstance("Botan", "Botan");

        byte[] bytes1 = new byte[32];
        byte[] bytes2 = new byte[32];

        rng1.nextBytes(bytes1);
        rng2.nextBytes(bytes2);

        // Different instances should produce different random values
        assertFalse(Arrays.equals(bytes1, bytes2),
                "Different RNG instances should produce different output");
    }

    @Test
    @DisplayName("Test all RNG types produce unique output")
    void testAllRngTypes() throws Exception {
        String[] rngTypes = {"Botan", "BotanUser", "BotanUserThreadsafe"};
        Set<String> outputs = new HashSet<>();

        for (String type : rngTypes) {
            SecureRandom rng = SecureRandom.getInstance(type, "Botan");
            byte[] bytes = new byte[32];
            rng.nextBytes(bytes);

            String output = Arrays.toString(bytes);
            outputs.add(output);
        }

        assertEquals(rngTypes.length, outputs.size(),
                "All RNG types should produce unique output");
    }

    @Test
    @DisplayName("Test reseed with 256 bits")
    void testReseed256() throws Exception {
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
    }

    @Test
    @DisplayName("Test reseed with 384 bits")
    void testReseed384() throws Exception {
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
    }

    @Test
    @DisplayName("Test nextInt method")
    void testNextInt() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        // Test basic nextInt
        int value = rng.nextInt();
        assertNotNull(value); // Just ensure it doesn't crash

        // Test nextInt with bound
        int boundedValue = rng.nextInt(100);
        assertTrue(boundedValue >= 0 && boundedValue < 100,
                "nextInt(100) should be in range [0, 100)");
    }

    @Test
    @DisplayName("Test nextLong method")
    void testNextLong() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("Botan", "Botan");

        long value = rng.nextLong();
        assertNotNull(value); // Just ensure it doesn't crash
    }

    @Test
    @DisplayName("Test nextBoolean method")
    void testNextBoolean() throws Exception {
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
        assertTrue(trueRatio > 0.30 && trueRatio < 0.70,
                "nextBoolean should produce roughly 50% true values (got " + (trueRatio * 100) + "%)");
    }

    @Test
    @DisplayName("Test concurrent access to threadsafe RNG")
    void testThreadsafeRng() throws Exception {
        SecureRandom rng = SecureRandom.getInstance("BotanUserThreadsafe", "Botan");

        int numThreads = 10;
        int bytesPerThread = 1024;
        Thread[] threads = new Thread[numThreads];
        byte[][] results = new byte[numThreads][bytesPerThread];

        for (int i = 0; i < numThreads; i++) {
            final int index = i;
            threads[i] = new Thread(() -> rng.nextBytes(results[index]));
            threads[i].start();
        }

        // Wait for all threads
        for (Thread thread : threads) {
            thread.join();
        }

        // Verify all outputs are different
        Set<String> uniqueOutputs = new HashSet<>();
        for (byte[] result : results) {
            uniqueOutputs.add(Arrays.toString(result));
        }

        assertEquals(numThreads, uniqueOutputs.size(),
                "Threadsafe RNG should produce unique output for each thread");
    }
}
