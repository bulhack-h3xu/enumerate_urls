#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update and install prerequisites
sudo apt-get update
sudo apt-get install -y python3 python3-pip git curl

# Check if Go is installed, if not, install it
if ! command_exists go; then
    echo "Installing Go..."
    curl -OL https://golang.org/dl/go1.16.6.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.16.6.linux-amd64.tar.gz
    echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.profile
    source ~/.profile
fi

# Install tools using Go
echo "Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "Installing assetfinder..."
go install -v github.com/tomnomnom/assetfinder@latest

echo "Installing amass..."
go install -v github.com/OWASP/Amass/v3/...@master

echo "Installing waybackurls..."
go install github.com/tomnomnom/waybackurls@latest

echo "Installing gau..."
go install github.com/lc/gau/v2/cmd/gau@latest

echo "Installing katana..."
go install github.com/projectdiscovery/katana/cmd/katana@latest

echo "Installing httpx..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Add Go binaries to PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Install Python packages
echo "Installing Python packages..."
pip3 install tqdm aiofiles

# Check if enumerate_urls.py exists in the current directory
if [ -f ./enumerate_urls.py ]; then
    # Move the downloaded enumerate_urls.py script to /usr/bin/ and replace any existing one
    echo "Moving enumerate_urls.py to /usr/bin/enum_urls.py"
    sudo mv ./enumerate_urls.py /usr/bin/enum_urls.py
    sudo chmod +x /usr/bin/enum_urls.py
else
    echo "enumerate_urls.py not found in the current directory."
fi

echo "All required tools and dependencies have been installed."
