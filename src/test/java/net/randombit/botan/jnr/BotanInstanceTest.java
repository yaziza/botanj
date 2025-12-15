/*
 * (C) 2025 Yasser Aziza
 *
 * Botanj is released under the MIT License (see license.txt)
 *
 * Contributors:
 *    Yasser Aziza - initial implementation
 */

package net.randombit.botan.jnr;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.jdi.NativeMethodException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Test cases for BotanInstance class to improve coverage. */
class BotanInstanceTest {

  private static final Logger LOG = LogManager.getLogger(BotanInstanceTest.class);

  @BeforeAll
  static void setUp() {
    LOG.info("=== Botan Instance Test Suite ===");
  }

  @Test
  void testSingletonNotNull() {
    LOG.info("=== Test: Singleton returns non-null instance ===");
    // Test that singleton returns a valid instance when library is loaded
    BotanLibrary library = BotanInstance.singleton();
    assertNotNull(library, "Singleton should return non-null library instance");
    LOG.info("SUCCESS: Singleton returned non-null BotanLibrary instance");
  }

  @Test
  void testCheckAvailabilitySucceeds() {
    LOG.info("=== Test: Check availability succeeds ===");
    // Test that checkAvailability doesn't throw when library is available
    assertDoesNotThrow(
        () -> BotanInstance.checkAvailability(),
        "checkAvailability should not throw when library is loaded");
    LOG.info("SUCCESS: checkAvailability() completed without throwing");
  }

  @Test
  void testCheckNativeCallSuccess() {
    LOG.info("=== Test: Check native call success (result=0) ===");
    // Test successful native call (result = 0)
    assertDoesNotThrow(
        () -> BotanInstance.checkNativeCall(0, "test_method"),
        "checkNativeCall should not throw for success result (0)");
    LOG.info("SUCCESS: checkNativeCall(0, 'test_method') did not throw");
  }

  @Test
  void testCheckNativeCallFailure() {
    LOG.info("=== Test: Check native call failure (result=-1) ===");
    // Test failed native call (result != 0)
    // This should throw NativeMethodException
    assertThrows(
        NativeMethodException.class,
        () -> BotanInstance.checkNativeCall(-1, "test_method"),
        "checkNativeCall should throw NativeMethodException for non-zero result");
    LOG.info("SUCCESS: checkNativeCall(-1, 'test_method') threw NativeMethodException as expected");
  }

  @Test
  void testSingletonConsistency() {
    LOG.info("=== Test: Singleton consistency ===");
    // Test that singleton always returns the same instance
    BotanLibrary first = BotanInstance.singleton();
    BotanLibrary second = BotanInstance.singleton();
    LOG.info("First instance: {}", first.getClass().getName());
    LOG.info("Second instance: {}", second.getClass().getName());
    assertSame(first, second, "Singleton should always return the same instance");
    LOG.info("SUCCESS: Both calls to singleton() returned the same instance");
  }

  @Test
  void testVersionString() {
    LOG.info("=== Test: Get Botan version string ===");
    // Test that we can call a simple native method
    BotanLibrary library = BotanInstance.singleton();
    assertNotNull(library);

    String version = library.botan_version_string();
    assertNotNull(version, "Version string should not be null");
    assertFalse(version.isEmpty(), "Version string should not be empty");
    LOG.info("Botan version: {}", version);
    // Version string format is like "Botan 3.10.0 (revision unknown, distribution unspecified)"
    assertTrue(version.contains("3."), "Version should contain 3. (current major version)");
    LOG.info("SUCCESS: Retrieved Botan version string");
  }

  @Test
  void testErrorDescription() {
    LOG.info("=== Test: Get error description for error code ===");
    // Test that we can get error descriptions
    BotanLibrary library = BotanInstance.singleton();
    assertNotNull(library);

    // Get error description for a known error code
    String errorDesc = library.botan_error_description(-1);
    assertNotNull(errorDesc, "Error description should not be null");
    assertFalse(errorDesc.isEmpty(), "Error description should not be empty");
    LOG.info("Error code -1 description: '{}'", errorDesc);
    LOG.info("SUCCESS: Retrieved error description for error code -1");
  }
}
