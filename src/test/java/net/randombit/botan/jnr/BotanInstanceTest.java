/*
 * (C) 2020 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.jnr;

import com.sun.jdi.NativeMethodException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test cases for BotanInstance class to improve coverage.
 */
class BotanInstanceTest {

    @Test
    void testSingletonNotNull() {
        // Test that singleton returns a valid instance when library is loaded
        BotanLibrary library = BotanInstance.singleton();
        assertNotNull(library, "Singleton should return non-null library instance");
    }

    @Test
    void testCheckAvailabilitySucceeds() {
        // Test that checkAvailability doesn't throw when library is available
        assertDoesNotThrow(() -> BotanInstance.checkAvailability(),
                "checkAvailability should not throw when library is loaded");
    }

    @Test
    void testCheckNativeCallSuccess() {
        // Test successful native call (result = 0)
        assertDoesNotThrow(() -> BotanInstance.checkNativeCall(0, "test_method"),
                "checkNativeCall should not throw for success result (0)");
    }

    @Test
    void testCheckNativeCallFailure() {
        // Test failed native call (result != 0)
        // This should throw NativeMethodException
        assertThrows(NativeMethodException.class,
                () -> BotanInstance.checkNativeCall(-1, "test_method"),
                "checkNativeCall should throw NativeMethodException for non-zero result");
    }

    @Test
    void testSingletonConsistency() {
        // Test that singleton always returns the same instance
        BotanLibrary first = BotanInstance.singleton();
        BotanLibrary second = BotanInstance.singleton();
        assertSame(first, second, "Singleton should always return the same instance");
    }

    @Test
    void testVersionString() {
        // Test that we can call a simple native method
        BotanLibrary library = BotanInstance.singleton();
        assertNotNull(library);

        String version = library.botan_version_string();
        assertNotNull(version, "Version string should not be null");
        assertFalse(version.isEmpty(), "Version string should not be empty");
        // Version string format is like "Botan 3.10.0 (revision unknown, distribution unspecified)"
        assertTrue(version.contains("3."), "Version should contain 3. (current major version)");
    }

    @Test
    void testErrorDescription() {
        // Test that we can get error descriptions
        BotanLibrary library = BotanInstance.singleton();
        assertNotNull(library);

        // Get error description for a known error code
        String errorDesc = library.botan_error_description(-1);
        assertNotNull(errorDesc, "Error description should not be null");
        assertFalse(errorDesc.isEmpty(), "Error description should not be empty");
    }
}
