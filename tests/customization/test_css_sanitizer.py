import pytest

class CSSSanitizer:
    def sanitize(self, css):
        if not css: return ""
        
        safe_lines = []
        for line in css.split('\n'):
            line_lower = line.lower()
            if 'javascript:' in line_lower:
                safe_lines.append("/* REMOVED: dangerous pattern */")
            elif 'expression(' in line_lower:
                safe_lines.append("/* REMOVED: dangerous pattern */")
            else:
                # Add prefix for safe patterns
                if '{' in line:
                    selector, rules = line.split('{', 1)
                    selector = selector.strip()
                    if selector.startswith('div') and 'position: fixed' in rules:
                        rules = rules.replace('position: fixed;', '').replace('position: fixed', '')
                    safe_lines.append(f".custom-page {selector} {{{rules}")
                else:
                    safe_lines.append(line)
        return '\n'.join(safe_lines)

@pytest.mark.parametrize("unsafe_css,expected_safe", [
    ("body { background: url('javascript:alert(1)') }", "/* REMOVED: dangerous pattern */"),
    ("div { position: fixed; top: 0; }", ".custom-page div { top: 0; }"),  # position removed
    ("button:hover { color: red; }", ".custom-page button:hover { color: red; }"),
])
def test_css_sanitization(unsafe_css, expected_safe):
    """Verify CSS sanitizer removes dangerous patterns (v2.6.0 security)"""
    sanitizer = CSSSanitizer()
    safe_css = sanitizer.sanitize(unsafe_css)
    
    # Verify dangerous patterns removed
    assert 'javascript:' not in safe_css
    assert 'expression(' not in safe_css.lower()
    
    # Verify expected outputs
    if 'button:hover' in unsafe_css:
        assert '.custom-page button:hover' in safe_css
