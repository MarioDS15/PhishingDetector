#!/usr/bin/env python3
"""
Create placeholder icons for Chrome extension
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_icon(size, output_path):
    """Create a simple shield icon"""
    # Create image with gradient background
    img = Image.new('RGB', (size, size), color='white')
    draw = ImageDraw.Draw(img)

    # Draw gradient background (purple)
    for i in range(size):
        color = int(102 + (118 - 102) * i / size)  # Gradient from #667eea to #764ba2
        draw.line([(0, i), (size, i)], fill=(color, 126, 234))

    # Draw shield shape
    shield_color = (255, 255, 255)
    margin = int(size * 0.2)

    # Shield outline
    points = [
        (size // 2, margin),  # Top center
        (size - margin, margin + size // 6),  # Top right
        (size - margin, size // 2),  # Middle right
        (size // 2, size - margin),  # Bottom center
        (margin, size // 2),  # Middle left
        (margin, margin + size // 6),  # Top left
    ]

    draw.polygon(points, fill=shield_color, outline=(200, 200, 200))

    # Draw a simple "!" symbol in the center
    center_x, center_y = size // 2, size // 2 + int(size * 0.05)

    # Draw exclamation mark parts
    if size >= 32:
        # Draw ! line
        line_width = max(2, size // 16)
        line_height = int(size * 0.25)
        draw.rectangle([center_x - line_width, center_y - line_height,
                       center_x + line_width, center_y],
                      fill=(102, 126, 234))

        # Draw ! dot
        dot_size = max(2, size // 24)
        draw.ellipse([center_x - dot_size, center_y + dot_size * 2,
                     center_x + dot_size, center_y + dot_size * 4],
                    fill=(102, 126, 234))
    else:
        # Just a small circle for tiny icons
        symbol_size = max(2, size // 8)
        draw.ellipse([center_x - symbol_size, center_y - symbol_size,
                     center_x + symbol_size, center_y + symbol_size],
                    fill=(102, 126, 234))

    img.save(output_path)
    print(f"Created {output_path}")

def main():
    # Create images directory
    img_dir = 'extension/images'
    os.makedirs(img_dir, exist_ok=True)

    # Create icons in different sizes
    sizes = [16, 32, 48, 128]

    for size in sizes:
        output_path = os.path.join(img_dir, f'icon{size}.png')
        create_icon(size, output_path)

    print("\n✅ All icons created successfully!")
    print(f"Icons saved in: {img_dir}/")

if __name__ == "__main__":
    try:
        main()
    except ImportError:
        print("PIL/Pillow not installed. Creating simple placeholder icons...")
        print("Install with: pip install Pillow")
        print("Or create icons manually in extension/images/ directory")
