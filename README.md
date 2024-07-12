# URL and Parameter Enumeration Tool

This tool is designed for security researchers and penetration testers to gather URLs and parameters from a target website for testing purposes. It utilizes multiple tools to perform comprehensive enumeration and extracts parameters for further analysis.

## Features

- Subdomain enumeration using `subfinder`, `assetfinder`, and `amass`
- URL gathering using `waybackurls`, `getallurls`, and `gau`
- Web crawling using `katana`
- Parallel execution for speed
- Extracts and filters URLs with and without query parameters
- Outputs unique URLs and parameters

## Prerequisites

- Python 3.x
- Go

## Installation

To install all necessary dependencies, run the following script:

```sh
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

# Add Go binaries to PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Install Python packages
echo "Installing Python packages..."
pip3 install tqdm

echo "All required tools and dependencies have been installed."
