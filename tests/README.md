# Gibson Framework Test Suite

## Test Structure

Our test suite follows **Test-Driven Development (TDD)** principles and is organized by test type:

```
tests/
├── conftest.py           # Shared fixtures for all tests
├── pytest.ini            # Pytest configuration
├── unit/                 # Unit tests - test individual components
│   └── core/
│       └── payloads/
│           ├── test_url_parser_platform_detection.py  # Platform detection bug tests
│           └── test_url_parser.py                     # General URL parser tests
├── integration/          # Integration tests - test component interactions
│   └── core/
│       └── payloads/
│           ├── test_sync_flow.py         # Full sync workflow tests
│           └── test_auth_integration.py  # Authentication flow tests
└── e2e/                  # End-to-end tests - test complete user workflows
    └── test_cli_sync_command.py          # CLI command tests
```

## TDD Workflow

### 1. Red Phase (Write Failing Test)
```python
# Write a test that demonstrates the bug
def test_github_url_not_detected_as_gogs(url_parser):
    url = "https://github.com/zero-day-ai/gibson-prompt-library"
    git_url = url_parser.parse(url)
    assert git_url.platform == GitPlatform.GITHUB  # This fails with bug
```

### 2. Green Phase (Make Test Pass)
Fix the minimal code to make the test pass.

### 3. Refactor Phase (Improve Code)
Refactor while keeping tests green.

## Running Tests

### Run All Tests
```bash
pytest
```

### Run Specific Test Types
```bash
# Unit tests only
pytest tests/unit -m unit

# Integration tests only
pytest tests/integration -m integration

# End-to-end tests only
pytest tests/e2e -m e2e
```

### Run Tests for Debugging the GOGS Bug
```bash
# Run the failing test to confirm bug
pytest tests/unit/core/payloads/test_url_parser_platform_detection.py::TestPlatformDetectionBug::test_github_url_not_detected_as_gogs

# Run with debug output
pytest -s tests/e2e/test_cli_sync_command.py::TestCLIErrorReproduction::test_diagnose_gogs_error

# Run all platform detection tests
pytest tests/unit/core/payloads/test_url_parser_platform_detection.py -v
```

### Run with Coverage
```bash
pytest --cov=gibson --cov-report=html
```

## Test Organization Patterns

### Unit Tests
- Test single functions/methods in isolation
- Mock all external dependencies
- Fast execution (< 0.1s per test)
- Located in `tests/unit/`

Example:
```python
def test_detect_platform_github(url_parser):
    """Test that GitHub URLs are correctly identified."""
    platform = url_parser.detect_platform("https://github.com/owner/repo")
    assert platform == GitPlatform.GITHUB
```

### Integration Tests
- Test multiple components working together
- Mock external services (network, database)
- Medium speed (< 1s per test)
- Located in `tests/integration/`

Example:
```python
def test_url_parser_with_auth_factory(url_parser, auth_factory):
    """Test URL parser integrates with auth factory."""
    git_url = url_parser.parse("https://github.com/owner/repo")
    provider = auth_factory.get_provider(git_url)
    assert provider.platform_name == "github"
```

### End-to-End Tests
- Test complete user workflows
- Minimal mocking (only external services)
- Can be slower (> 1s per test)
- Located in `tests/e2e/`

Example:
```python
async def test_sync_repository_command():
    """Test the complete sync command as a user would run it."""
    result = await sync_repository("https://github.com/owner/repo")
    assert result.success
```

## Fixtures (conftest.py)

Fixtures provide reusable test data and setup:

```python
@pytest.fixture
def url_parser():
    """Provides a URLParser instance."""
    return URLParser()

@pytest.fixture
def github_urls():
    """Collection of GitHub URLs for testing."""
    return [
        "https://github.com/owner/repo",
        "git@github.com:owner/repo.git",
    ]
```

Use fixtures by adding them as test parameters:
```python
def test_parse_github_urls(url_parser, github_urls):
    for url in github_urls:
        git_url = url_parser.parse(url)
        assert git_url.platform == GitPlatform.GITHUB
```

## Debugging Tests

### See Print Output
```bash
pytest -s  # Don't capture output
```

### Run Specific Test
```bash
pytest path/to/test.py::TestClass::test_method
```

### Stop on First Failure
```bash
pytest -x
```

### Run Failed Tests from Last Run
```bash
pytest --lf  # last failed
pytest --ff  # failed first
```

### Verbose Output
```bash
pytest -vv  # Very verbose
```

## Best Practices

1. **One Assertion Per Test**: Each test should verify one specific behavior
2. **Descriptive Names**: Test names should describe what they test
3. **Arrange-Act-Assert**: Structure tests clearly
4. **Use Fixtures**: Don't repeat setup code
5. **Mock External Dependencies**: Keep tests fast and deterministic
6. **Test Edge Cases**: Don't just test the happy path
7. **Keep Tests Independent**: Tests shouldn't depend on each other

## The GOGS Bug

The current bug where GitHub URLs are detected as GOGS can be debugged using:

1. **Failing Unit Test**: 
   ```bash
   pytest tests/unit/core/payloads/test_url_parser_platform_detection.py::TestPlatformDetectionBug
   ```

2. **Debug Diagnostic**:
   ```bash
   pytest -s tests/e2e/test_cli_sync_command.py::TestCLIErrorReproduction::test_diagnose_gogs_error
   ```

3. **Full Platform Test**:
   ```bash
   pytest tests/unit/core/payloads/test_url_parser_platform_detection.py -v
   ```

The fix should ensure GitHub detection happens before GOGS in the platform detection logic.