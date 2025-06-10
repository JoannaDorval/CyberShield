#!/usr/bin/env python3
"""
Dependency Checker for TARA Desktop Application
Checks if all required files and Python packages are available
"""

import sys
import os
from pathlib import Path

def check_python_packages():
    """Check if required Python packages are installed"""
    required_packages = [
        'tkinter',
        'pandas', 
        'openpyxl',
        'pillow',
        'reportlab',
        'requests',
        'yaml'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            if package == 'tkinter':
                import tkinter
            elif package == 'pandas':
                import pandas
            elif package == 'openpyxl':
                import openpyxl
            elif package == 'pillow':
                from PIL import Image
            elif package == 'reportlab':
                import reportlab
            elif package == 'requests':
                import requests
            elif package == 'yaml':
                import yaml
            print(f"✓ {package} - OK")
        except ImportError:
            print(f"✗ {package} - MISSING")
            missing_packages.append(package)
    
    return missing_packages

def check_required_files():
    """Check if all required Python files are present"""
    required_files = [
        'tara_desktop.py',
        'parsers.py',
        'mitre_integration.py', 
        'mitre_embed.py',
        'pdf_generator.py',
        'enhanced_excel_generator.py'
    ]
    
    missing_files = []
    current_dir = Path.cwd()
    
    for file in required_files:
        file_path = current_dir / file
        if file_path.exists():
            print(f"✓ {file} - OK")
        else:
            print(f"✗ {file} - MISSING")
            missing_files.append(file)
    
    return missing_files

def main():
    print("TARA Desktop Application - Dependency Check")
    print("=" * 50)
    
    print("\nChecking Python packages...")
    missing_packages = check_python_packages()
    
    print("\nChecking required files...")
    missing_files = check_required_files()
    
    print("\n" + "=" * 50)
    
    if missing_packages:
        print(f"\nMissing Python packages: {', '.join(missing_packages)}")
        print("Install with: pip install " + " ".join(missing_packages))
        
        # Handle special cases
        if 'yaml' in missing_packages:
            print("Note: For yaml, install with: pip install pyyaml")
        if 'pillow' in missing_packages:
            print("Note: For pillow, install with: pip install Pillow")
    
    if missing_files:
        print(f"\nMissing required files: {', '.join(missing_files)}")
        print("Download these files from the Replit project")
    
    if not missing_packages and not missing_files:
        print("\n✓ All dependencies satisfied! You can run the desktop app.")
        print("Run with: python tara_desktop.py")
    else:
        print(f"\n✗ {len(missing_packages + missing_files)} issues found. Please resolve them first.")

if __name__ == "__main__":
    main()