#!/bin/bash

# Update & Install dependencies
echo "[+] Updating system and installing dependencies..."
sudo apt update 

# Install Amass
echo "[+] Installing Amass..."
wget -q https://github.com/owasp-amass/amass/releases/download/v3.23.3/amass_Linux_amd64.zip
unzip -q amass_Linux_amd64.zip
chmod +x amass
sudo mv amass /usr/bin/
rm -f amass_Linux_amd64.zip

# Install Go (if not installed)
if ! command -v go &> /dev/null; then
    echo "[+] Installing Go..."
    sudo apt install golang
fi

# Set Go environment variables
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Install Golang tools
echo "[+] Installing Go-based recon tools..."
TOOLS=(
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/incogbyte/shosubgo@latest"
    "github.com/gwen001/github-subdomains@latest"
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/OJ/gobuster/v3@latest"
)

for tool in "${TOOLS[@]}"; do
    go install -v "$tool"
done

# Move binaries to /usr/local/bin
echo "[+] Moving Go binaries to /usr/local/bin..."
sudo mv ~/go/bin/* /usr/local/bin/ 2>/dev/null || true

# Install Findomain
echo "[+] Installing Findomain..."
curl -sLO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip -q findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/findomain
rm -f findomain-linux.zip

# Install Python tools
echo "[+] Installing Shodan and Censys Python libraries..."
pip3 install --break-system-packages shodan censys

# Installation complete
echo "[+] Installation complete! Type 'source ~/.bashrc' or restart your terminal to apply changes."
