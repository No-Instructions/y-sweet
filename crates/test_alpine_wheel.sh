#!/bin/bash
set -euo pipefail

# Path to the Alpine wheel
ALPINE_WHEEL="/home/daniel/stash/y-sweet/alpine_wheels/y_sign-0.8.1-cp310-cp310-musllinux_1_2_x86_64.whl"

# Check if wheel exists
if [ ! -f "$ALPINE_WHEEL" ]; then
    echo "❌ Alpine wheel not found at $ALPINE_WHEEL"
    echo "   Please run build_python_alpine.sh first"
    exit 1
fi

echo "🧪 Testing Alpine wheel installation in a clean Alpine container..."

# Run test in Alpine container
WHEEL_BASENAME=$(basename "$ALPINE_WHEEL")
docker run --rm -v "$ALPINE_WHEEL:/app/$WHEEL_BASENAME" -w /app python:3.10-alpine sh <<'EOFSH'
echo "📦 Installing wheel..."
pip install $WHEEL_BASENAME

echo "🔍 Testing import..."
if python -c "import y_sign; print('✅ Successfully imported y_sign')"; then
    echo "🎉 Test passed! The wheel works on Alpine Linux."
else
    echo "❌ Test failed! Could not import y_sign module."
    exit 1
fi

echo "🧩 Testing functionality..."
python -c "
import y_sign
print('Generating token...')
token = y_sign.gen_doc_token('test-key', 'test-doc', False, 3600)
print(f'Token: {token[:20]}...')
print('Verifying token...')
result = y_sign.verify_doc_token('test-key', token, 'test-doc')
print(f'Result: {result}')
print('✅ Functionality test passed!')
"
EOFSH

echo "✨ All tests passed! The wheel is compatible with Alpine Linux."