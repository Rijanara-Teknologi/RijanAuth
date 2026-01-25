# -*- encoding: utf-8 -*-
"""
RijanAuth - Customization Renderer
Helper functions for rendering pages with customization
"""

from flask import render_template, url_for
from apps.models.customization import RealmPageCustomization
from apps.utils.css_sanitizer import CSSSanitizer
from apps.utils.media_handler import MediaHandler


def get_page_customization(realm_id, page_type='login'):
    """
    Get realm-specific customization for given page type
    
    Args:
        realm_id: Realm ID
        page_type: Page type ('login', 'register', 'forgot_password', 'consent', 'error')
        
    Returns:
        Dictionary with customization settings
    """
    customization = RealmPageCustomization.get(realm_id, page_type)
    
    if not customization:
        # Return default customization
        return {
            'background_type': 'gradient',
            'background_gradient': {
                'colors': ['#673AB7', '#3F51B5'],
                'direction': 'to right'
            },
            'background_color': '#673AB7',
            'background_image_id': None,
            'background_image_url': None,
            'primary_color': '#673AB7',
            'secondary_color': '#3F51B5',
            'font_family': 'Inter, system-ui, -apple-system, sans-serif',
            'button_radius': 4,
            'form_radius': 4,
            'logo_id': None,
            'logo_url': None,
            'logo_position': 'center',
            'custom_css': '',
            'safe_css': ''
        }
    
    # Build customization dict
    custom_dict = {
        'background_type': customization.background_type,
        'background_color': customization.background_color,
        'background_gradient': customization.get_background_gradient_dict(),
        'background_image_id': customization.background_image_id,
        'background_image_url': None,
        'primary_color': customization.primary_color,
        'secondary_color': customization.secondary_color,
        'font_family': customization.font_family,
        'button_radius': customization.button_radius,
        'form_radius': customization.form_radius,
        'logo_id': customization.logo_id,
        'logo_url': None,
        'logo_position': customization.logo_position,
        'custom_css': customization.custom_css or '',
        'safe_css': ''
    }
    
    # Get media URLs
    if customization.background_image_id:
        from apps.models.customization import MediaAsset
        bg_asset = MediaAsset.find_by_id(customization.background_image_id)
        if bg_asset:
            custom_dict['background_image_url'] = MediaHandler.get_file_url(bg_asset)
    
    if customization.logo_id:
        from apps.models.customization import MediaAsset
        logo_asset = MediaAsset.find_by_id(customization.logo_id)
        if logo_asset:
            custom_dict['logo_url'] = MediaHandler.get_file_url(logo_asset)
    
    # Sanitize custom CSS
    if customization.custom_css:
        sanitized, _ = CSSSanitizer.sanitize(customization.custom_css, add_prefix=True)
        custom_dict['safe_css'] = sanitized
    
    return custom_dict


def render_custom_page(template_name, realm, page_type='login', **context):
    """
    Render page with customization applied
    
    Args:
        template_name: Template name (e.g., 'auth/login.html')
        realm: Realm object
        page_type: Page type for customization
        **context: Additional template context
        
    Returns:
        Rendered template
    """
    # Get customization
    customization = get_page_customization(realm.id, page_type)
    
    # Add customization to context
    context.update({
        'customization': customization,
        'realm': realm
    })
    
    # Render template
    return render_template(template_name, **context)


def get_customization_css_variables(customization):
    """
    Generate CSS variables from customization
    
    Args:
        customization: Customization dictionary
        
    Returns:
        CSS string with CSS variables
    """
    css_vars = []
    css_vars.append(f"  --primary-color: {customization.get('primary_color', '#673AB7')};")
    css_vars.append(f"  --secondary-color: {customization.get('secondary_color', '#3F51B5')};")
    css_vars.append(f"  --button-radius: {customization.get('button_radius', 4)}px;")
    css_vars.append(f"  --form-radius: {customization.get('form_radius', 4)}px;")
    css_vars.append(f"  --font-family: {customization.get('font_family', 'Inter, system-ui, -apple-system, sans-serif')};")
    
    return '\n'.join(css_vars)


def get_customization_background_style(customization):
    """
    Generate background style from customization
    
    Args:
        customization: Customization dictionary
        
    Returns:
        CSS style string for background
    """
    bg_type = customization.get('background_type', 'color')
    
    if bg_type == 'image' and customization.get('background_image_url'):
        return f"background-image: url('{customization['background_image_url']}'); background-size: cover; background-position: center; background-repeat: no-repeat;"
    elif bg_type == 'gradient':
        gradient = customization.get('background_gradient')
        if gradient and 'colors' in gradient and len(gradient['colors']) >= 2:
            colors = ', '.join(gradient['colors'])
            direction = gradient.get('direction', 'to right')
            return f"background: linear-gradient({direction}, {colors});"
        else:
            # Fallback to color
            return f"background-color: {customization.get('background_color', '#673AB7')};"
    else:
        # Color
        return f"background-color: {customization.get('background_color', '#673AB7')};"
