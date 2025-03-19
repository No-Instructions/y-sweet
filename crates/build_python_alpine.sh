#!/bin/bash
set -euo pipefail

# Package information
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PYTHON_SRC="${REPO_ROOT}/python/y-sign-py"
OUTPUT_DIR="${REPO_ROOT}/alpine_wheels"

echo "🔍 Building y-sign Python wheel for Alpine"
echo "   Source: ${PYTHON_SRC}"
echo "   Output: ${OUTPUT_DIR}"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Create a temporary Dockerfile
cat > Dockerfile.alpine_build << 'EOF'
FROM python:3.10-alpine

env CARGO_HOME=/build

# Install build dependencies
RUN apk add --no-cache \
    cargo \
    rust \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    build-base \
    git

# Install maturin
RUN apk add --no-cache patchelf && \
    pip install --upgrade pip "maturin[patchelf]==1.3.0"

# Set up working directory
WORKDIR /build

# Build with static linking for musl compatibility
CMD cd /src && \
    # Build the wheel
    maturin build \
    --release \
    -i python3.10 \
    --strip && \
    mkdir -p /output && \
    cp target/wheels/*.whl /output/ && \
    # Only copy musllinux wheel for Python 3.10 to output
    cp target/wheels/*cp310*musllinux*.whl /output/alpine-wheel.whl
EOF

echo "🐳 Building Docker image for Alpine build environment..."
docker build -t alpine-rust-python-builder -f Dockerfile.alpine_build .

BUILD_DIR=$(mktemp -d)
echo "📁 Creating temp dir ${BUILD_DIR} for /build"

echo "🔨 Building wheel inside Alpine container..."
docker run --rm \
  --user $(id -u):$(id -g) \
  -v "${PYTHON_SRC}:/src" \
  -v "${REPO_ROOT}/crates/y-sweet-core:/crates/y-sweet-core" \
  -v "${OUTPUT_DIR}:/output" \
  -v "${BUILD_DIR}:/build" \
  alpine-rust-python-builder

echo "✅ Build complete! Wheels are available in ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}"

# Cleanup
rm Dockerfile.alpine_build
rm -r $BUILD_DIR

echo "📦 You can install the Alpine-compatible wheel using:"
echo "pip install ${OUTPUT_DIR}/alpine-wheel.whl"
