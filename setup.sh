#!/bin/bash
echo "=== NEXUS-IR Setup Script ==="
echo "Installing forensic dependencies..."
sudo apt-get install -y sleuthkit foremost binwalk yara \
    libimage-exiftool-perl 2>/dev/null
pip3 install volatility3 --break-system-packages 2>/dev/null
echo "✅ Dependencies installed"
echo "Installing Protocol SIFT..."
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash 2>/dev/null || echo "Protocol SIFT already installed"
echo "✅ Protocol SIFT ready"
export CASE=FINDEVIL-2026-001
mkdir -p ~/cases/${CASE}/{analysis,exports,reports}
echo "✅ Case structure created"
echo ""
echo "=== Setup Complete! Run the agent: ==="
echo "python3 cases/analysis/findevil_agent.py"
