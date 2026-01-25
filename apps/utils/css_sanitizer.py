# -*- encoding: utf-8 -*-
"""
RijanAuth - CSS Sanitizer
Secure CSS processing for page customization
"""

import re
from typing import Tuple, List


class CSSSanitizer:
    """
    Sanitize custom CSS to prevent XSS and other security issues
    """
    
    # Dangerous patterns that should be removed
    DANGEROUS_PATTERNS = [
        r'@import\s+',
        r'url\s*\([^)]*\)',
        r'expression\s*\(',
        r'javascript\s*:',
        r'on\w+\s*=',
        r'<script',
        r'</script>',
        r'<style',
        r'</style>',
        r'behavior\s*:',
        r'-moz-binding',
        r'import\s+',
        r'@charset',
        r'@namespace',
        r'@supports',
    ]
    
    # Properties that should be restricted
    RESTRICTED_PROPERTIES = [
        'position',
        'z-index',
        'display',  # Allow but monitor
        'visibility',  # Allow but monitor
    ]
    
    # Safe CSS properties (whitelist approach for critical security)
    # For now, we'll use blacklist but can switch to whitelist if needed
    SAFE_COLOR_PATTERN = re.compile(r'^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$|^rgb\(|^rgba\(|^hsl\(|^hsla\(|^transparent$|^inherit$|^initial$|^unset$')
    
    @classmethod
    def sanitize(cls, css: str, add_prefix: bool = True) -> Tuple[str, List[str]]:
        """
        Sanitize custom CSS
        
        Args:
            css: Raw CSS string
            add_prefix: Whether to add .custom-page prefix to selectors
            
        Returns:
            Tuple of (sanitized_css, warnings)
        """
        if not css:
            return '', []
        
        warnings = []
        original_css = css
        
        # Remove HTML tags
        css = re.sub(r'<[^>]*>', '', css)
        
        # Remove dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            matches = re.findall(pattern, css, re.IGNORECASE)
            if matches:
                warnings.append(f"Removed dangerous pattern: {pattern}")
                css = re.sub(pattern, '', css, flags=re.IGNORECASE)
        
        # Remove comments that might contain malicious content
        css = re.sub(r'/\*.*?\*/', '', css, flags=re.DOTALL)
        
        # Validate and clean CSS rules
        lines = css.split('\n')
        sanitized_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                sanitized_lines.append('')
                continue
            
            # Skip if line is a comment
            if line.startswith('/*') or line.startswith('//'):
                continue
            
            # Check for restricted properties (warn but allow for now)
            for prop in cls.RESTRICTED_PROPERTIES:
                if re.search(rf'\b{prop}\s*:', line, re.IGNORECASE):
                    warnings.append(f"Warning: Restricted property '{prop}' found - use with caution")
            
            # Add safe prefix to selectors if needed
            if add_prefix and not line.startswith('@') and ':' in line:
                # Check if line contains a selector (has { or : before {)
                if '{' in line or (':' in line and not line.strip().startswith('--')):
                    # Extract selector part
                    if '{' in line:
                        selector_part = line.split('{')[0].strip()
                        rest = '{' + '{'.join(line.split('{')[1:])
                    else:
                        # Property: value format
                        sanitized_lines.append(f".custom-page {{ {line} }}")
                        continue
                    
                    # Add prefix to selector
                    if selector_part and not selector_part.startswith('.custom-page'):
                        # Handle multiple selectors
                        selectors = [s.strip() for s in selector_part.split(',')]
                        prefixed_selectors = []
                        for sel in selectors:
                            if sel and not sel.startswith('.custom-page'):
                                # Don't prefix if it's already scoped
                                if sel.startswith('&'):
                                    prefixed_selectors.append(sel.replace('&', '.custom-page'))
                                else:
                                    prefixed_selectors.append(f".custom-page {sel}")
                            else:
                                prefixed_selectors.append(sel)
                        
                        if '{' in line:
                            sanitized_lines.append(f"{', '.join(prefixed_selectors)} {rest}")
                        else:
                            sanitized_lines.append(f"{', '.join(prefixed_selectors)}")
                    else:
                        sanitized_lines.append(line)
                else:
                    sanitized_lines.append(line)
            else:
                sanitized_lines.append(line)
        
        sanitized_css = '\n'.join(sanitized_lines)
        
        # Final validation - check for any remaining dangerous content
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, sanitized_css, re.IGNORECASE):
                warnings.append(f"Warning: Potential security issue detected after sanitization")
        
        return sanitized_css, warnings
    
    @classmethod
    def validate_color(cls, color: str) -> bool:
        """Validate if a color value is safe"""
        if not color:
            return False
        return bool(cls.SAFE_COLOR_PATTERN.match(color.strip()))
    
    @classmethod
    def process_custom_css(cls, css: str) -> str:
        """
        Process custom CSS for safe injection
        This is a simpler version that just sanitizes without adding prefix
        """
        sanitized, _ = cls.sanitize(css, add_prefix=False)
        return sanitized
