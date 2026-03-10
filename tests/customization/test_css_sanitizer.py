"""
CSS Sanitizer Tests
Tests for the real CSSSanitizer from apps.utils.css_sanitizer.
"""
import pytest
from apps.utils.css_sanitizer import CSSSanitizer


@pytest.mark.parametrize("unsafe_css,should_be_absent", [
    ("body { background: url('javascript:alert(1)') }", "javascript:"),
    ("div { -moz-binding: url('evil.xml') }", "-moz-binding"),
    ("a { background: expression(alert(1)) }", "expression("),
    ("<script>alert(1)</script> body { color: red; }", "<script>"),
    ("@import url('https://evil.com/hack.css');", "@import"),
])
def test_css_sanitization(unsafe_css, should_be_absent):
    """Verify CSSSanitizer removes dangerous patterns (v2.6.0 security)."""
    sanitized, warnings = CSSSanitizer.sanitize(unsafe_css)
    assert should_be_absent.lower() not in sanitized.lower()
    # HTML tags are stripped silently, so we don't always get warnings
    if should_be_absent != '<script>':
        assert len(warnings) > 0


def test_safe_css_preserved():
    """Safe CSS rules should pass through with .custom-page prefix."""
    safe_css = "button:hover { color: red; }"
    sanitized, warnings = CSSSanitizer.sanitize(safe_css, add_prefix=True)
    assert '.custom-page' in sanitized
    assert 'color: red' in sanitized


def test_restricted_properties_warned():
    """Restricted properties (position, z-index) should produce warnings."""
    css = ".box { position: absolute; z-index: 999; }"
    sanitized, warnings = CSSSanitizer.sanitize(css)
    warning_text = ' '.join(warnings)
    assert 'position' in warning_text.lower() or 'z-index' in warning_text.lower()


def test_empty_css():
    """Empty input returns empty string and no warnings."""
    sanitized, warnings = CSSSanitizer.sanitize('')
    assert sanitized == ''
    assert warnings == []


def test_process_custom_css_no_prefix():
    """process_custom_css sanitizes without adding prefix."""
    css = "body { color: blue; }"
    result = CSSSanitizer.process_custom_css(css)
    assert 'color: blue' in result
