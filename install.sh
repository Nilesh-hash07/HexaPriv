#!/usr/bin/env bash
set -e

echo "Building Hexapriv package in release mode..."
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release -p hexapriv

BIN_PATH="target/release/hexapriv"

# Install to ~/.local/bin if available
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
install -m 755 "$BIN_PATH" "$INSTALL_DIR/hexapriv"

# Also install to ~/.cargo/bin if available
if [ -d "$HOME/.cargo/bin" ]; then
    install -m 755 "$BIN_PATH" "$HOME/.cargo/bin/hexapriv"
fi


echo "[+] Installation complete!"
echo "[+] Binary installed to: $INSTALL_DIR/hexapriv"
echo "[+] You can now run 'hexapriv' directly from any terminal window."
