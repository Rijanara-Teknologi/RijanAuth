"""
Color Customization Tests
Validate color format validation via CSSSanitizer.validate_color.
"""
import pytest
from apps.utils.css_sanitizer import CSSSanitizer


@pytest.mark.parametrize("color,expected_valid", [
    # Valid hex colors
    ('#673ab7', True),
    ('#FFF', True),
    ('#0066cc', True),
    # Valid CSS keywords
    ('transparent', True),
    ('inherit', True),
    ('initial', True),
    ('unset', True),
    # Valid function notations
    ('rgb(100, 50, 200)', True),
    ('rgba(100, 50, 200, 0.5)', True),
    ('hsl(270, 50%, 50%)', True),
    ('hsla(270, 50%, 50%, 0.5)', True),
    # Invalid colors
    ('673ab7', False),       # missing #
    ('#67a2', False),        # wrong length
    ('red', False),          # named colors not in whitelist
    ('', False),             # empty
    (None, False),           # None
    ('javascript:alert(1)', False),
])
def test_color_validation(color, expected_valid):
    """CSSSanitizer.validate_color correctly identifies valid and invalid colors."""
    assert CSSSanitizer.validate_color(color) == expected_valid
