# Contributing to Botanj

Thank you for your interest in contributing to Botanj! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Building the Project](#building-the-project)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)


## Getting Started

Botanj is a Java Security Provider (JSP) that implements parts of the Java Cryptography Extension (JCE) using the native Botan cryptography library.

Before contributing, please:

1. Review the project architecture in [TBA](TBA)
2. Check existing issues and pull requests to avoid duplicates
3. For major changes, open an issue first to discuss your proposed changes

## Development Setup

### Prerequisites

- **Java 17** or later
- **Maven 3.6+**
- **Botan library** (native cryptography library)
  - macOS: `brew install botan`
  - Linux: Install via package manager or build from source
  - Windows: Build from source or use prebuilt binaries

### Clone the Repository

```bash
git clone https://github.com/randombit/botanj.git
cd botanj
```

### Configure Native Library Path

Set the native library path for your system:

```bash
# macOS example
export NATIVE_LIB_PATH=/opt/homebrew/opt/botan/lib

# Or specify in Maven commands (see below)
```

## Building the Project

### Compile

```bash
mvn clean compile
```

### Package

```bash
mvn clean package
```

This creates two JARs in `target/`:
- `botan-<version>.jar` - Main JAR
- `botan-<version>-jar-with-dependencies.jar` - JAR with all dependencies

## Running Tests

### Run All Tests

```bash
# macOS example with custom Botan library path
mvn test -Dnative.lib.path=/opt/homebrew/opt/botan/lib
```

### Run Single Test Class

```bash
mvn test -Dtest=BotanMessageDigestTest
```

### Run Single Test Method

```bash
mvn test -Dtest=BotanMessageDigestTest#testSha256
```

### Generate Code Coverage Report

```bash
mvn jacoco:report
```

The coverage report will be available at `target/site/jacoco/index.html`.

## Code Style

This project follows **Google Java Style** with checkstyle enforcement.

### Running Checkstyle

```bash
# Run checkstyle with Google checks
mvn checkstyle:check -Dcheckstyle.config.location=checkstyle/google_checks.xml

# Or run as part of verify phase
mvn verify
```

### Style Guidelines

- **Indentation**: 2 spaces (no tabs)
- **Line length**: Maximum 100 characters
- **Javadoc**: Required for all public classes and methods
- **Naming conventions**:
  - Classes: `PascalCase`
  - Methods: `camelCase`
  - Constants: `UPPER_SNAKE_CASE`
  - Variables: `camelCase`

### Code Formatting

The project uses Google Java Style. Configure your IDE:

- **IntelliJ IDEA**: Install "google-java-format" plugin
- **Eclipse**: Import [google-java-format settings](https://github.com/google/styleguide)
- **VS Code**: Use "Language Support for Java" extension with Google formatter

### Suppressions

Some naming violations are intentionally suppressed in `checkstyle-suppressions.xml`:
- Native method names (must match C library)
- Standard cryptographic algorithm names (SHA1, HMAC, etc.)
- Test files (relaxed requirements)

## Submitting Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-rsa-support`
- `fix/memory-leak-in-cipher`
- `docs/update-readme`

### Commit Messages

Write clear, concise commit messages:

```
[category] brief description

Detailed explanation of changes (if needed).

Fixes #123
```

Categories: `feature`, `fix`, `refactor`, `test`, `docs`, `cleanup`

### Commit Signing

**All commits must be signed.** This ensures the authenticity and integrity of contributions.

#### Setting Up Commit Signing

1. **Generate a GPG key** (if you don't have one):
   ```bash
   gpg --full-generate-key
   ```

2. **List your GPG keys**:
   ```bash
   gpg --list-secret-keys --keyid-format=long
   ```

3. **Configure Git to use your GPG key**:
   ```bash
   git config --global user.signingkey YOUR_KEY_ID
   git config --global commit.gpgsign true
   ```

4. **Add your GPG key to GitHub**:
   - Export your public key: `gpg --armor --export YOUR_KEY_ID`
   - Go to GitHub Settings → SSH and GPG keys → New GPG key
   - Paste your public key

5. **Sign commits**:
   ```bash
   git commit -S -m "your commit message"
   ```

With `commit.gpgsign` set to `true`, all commits will be signed automatically.

### Pull Request Process

1. **Fork the repository** and create your branch from `master`
2. **Make your changes** following the code style guidelines
3. **Add tests** for new functionality
4. **Run the test suite** and ensure all tests pass:
   ```bash
   mvn clean verify
   ```
5. **Run checkstyle** and fix any violations:
   ```bash
   mvn checkstyle:check -Dcheckstyle.config.location=checkstyle/google_checks.xml
   ```
6. **Sign your commits** using GPG (required)
7. **Update documentation** if needed (README.md, etc.)
8. **Submit a pull request** with a clear description of your changes

### Pull Request Description Template

```markdown
## Description
Brief summary of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe how you tested your changes.

## Checklist
- [ ] Code follows the style guidelines
- [ ] Self-review completed
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] Checkstyle passes
- [ ] Documentation updated
```

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- **Description**: Clear description of the issue
- **Steps to reproduce**: Minimal code example
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened
- **Environment**:
  - Java version (`java -version`)
  - Botan version
  - OS and version
  - Maven version

### Feature Requests

For feature requests, please describe:

- **Use case**: Why is this feature needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches you've thought about

### Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

For security issues, please contact the maintainers directly via email.

## Architecture Guidelines

### Adding New Algorithms

When adding support for a new cryptographic algorithm:

1. **Check Botan support**: Verify the algorithm is supported in Botan
2. **Implement the JCE interface**:
   - Extend appropriate base class (`BotanMessageDigest`, `BotanMac`, etc.)
   - Implement required abstract methods
3. **Register in BotanProvider**: Add algorithm mapping in `BotanProvider.java`
4. **Add native bindings**: Update `BotanLibrary.java` if new FFI functions are needed
5. **Add tests**:
   - Create test vectors in `src/test/resources/`
   - Add parameterized tests
   - Include Bouncy Castle compatibility tests if applicable
6. **Update documentation**: Update README.md with supported algorithms

### Test Requirements

All contributions should include appropriate tests:

- **Unit tests**: Test individual components in isolation
- **Integration tests**: Test interaction with native Botan library
- **Test vectors**: Use standard test vectors where available
- **Compatibility tests**: Verify interoperability with other providers (e.g., Bouncy Castle)
- **Edge cases**: Test boundary conditions and error handling

### Documentation

Update documentation for:

- New features or algorithms
- API changes
- Configuration changes
- Build or setup changes

## Questions?

If you have questions about contributing, please:

1. Check existing documentation
2. Search existing issues
3. Open a new issue with the "question" label

## License

By contributing to Botanj, you agree that your contributions will be licensed under the MIT License.
