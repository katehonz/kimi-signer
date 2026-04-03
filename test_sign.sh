#!/bin/bash

# Test script for KIMI Signer
# Creates a test file and demonstrates signing functionality

echo "=== KIMI Signer Test ==="
echo ""
echo "Open Source Electronic Document Signing Application"
echo ""

# Create test directory
mkdir -p test_files

# Create a test document
echo "This is a test document for electronic signing." > test_files/test_document.txt
echo "Created: $(date)" >> test_files/test_document.txt
echo "Application: KIMI Signer" >> test_files/test_document.txt
echo "Content: Test document for CAdES/PKCS#7 signature" >> test_files/test_document.txt

echo "✓ Created test file: test_files/test_document.txt"
echo ""

# Check for PKCS#11 modules
echo "=== Checking for PKCS#11 modules ==="

modules=(
    "/usr/lib/libeTPkcs11.so"
    "/usr/lib64/libeTPkcs11.so"
    "/usr/lib/libbtrustpkcs11.so"
    "/usr/lib64/libbtrustpkcs11.so"
    "/usr/lib/libstampp11.so"
    "/usr/lib/libinnp11.so"
    "/usr/lib/opensc-pkcs11.so"
)

found=0
for module in "${modules[@]}"; do
    if [ -f "$module" ]; then
        echo "✓ Found: $module"
        found=1
    fi
done

if [ $found -eq 0 ]; then
    echo "⚠ No PKCS#11 modules found."
    echo "  Please install your eID provider software:"
    echo "  - B-Trust: https://www.b-trust.bg/"
    echo "  - InfoNotary: https://www.infonotary.com/"
    echo "  - StampIT: https://www.stampit.org/"
    echo "  - Gemalto/SafeNet: Check your token documentation"
fi

echo
echo "=== Build Status ==="
if [ -f "target/debug/kimi-signer" ]; then
    echo "✓ Debug build exists"
    echo "  Run: ./target/debug/kimi-signer"
fi
if [ -f "target/release/kimi-signer" ]; then
    echo "✓ Release build exists"
    echo "  Run: ./target/release/kimi-signer"
fi

echo
echo "=== Usage Instructions ==="
echo "1. Start the application:"
echo "   ./target/release/kimi-signer"
echo
echo "2. Select PKCS#11 library:"
echo "   - Click '📁 Избери библиотека'"
echo "   - Choose your token from the list or enter path manually"
echo
echo "3. Login with PIN:"
echo "   - Enter your token PIN"
echo "   - Click 'Вход'"
echo
echo "4. Select document:"
echo "   - Click '📁 Изберете файл'"
echo "   - Select: test_files/test_document.txt"
echo
echo "5. Configure signature:"
echo "   - Choose: Attached (.p7m) or Detached (.p7s)"
echo "   - Select output directory (optional)"
echo
echo "6. Select certificate:"
echo "   - Click '🔄 Обнови списъка'"
echo "   - Select your certificate"
echo
echo "7. Sign:"
echo "   - Click '✍️ Подпиши документа'"
echo "   - Enter PIN to confirm"
echo
echo "=== Test Output Directory ==="
echo "Signed files will be saved in: test_files/"
echo

# List test files
ls -la test_files/
