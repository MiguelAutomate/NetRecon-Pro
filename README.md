# NetRecon Pro

A comprehensive network reconnaissance tool combining powerful CLI and GUI interfaces for network security analysis and scanning.

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker Ready](https://img.shields.io/badge/docker-ready-blue)

## Features

- **Multiple Scanning Tools**:
  - Ping: Basic connectivity tests
  - Traceroute: Network path analysis
  - Nmap: Port and service scanning (stealth and aggressive modes)
  - Whois: Domain ownership lookups
  - DNS Lookup: DNS resolution and record analysis
  - SSL/TLS Analysis: Certificate and security configuration scanning
  - Comprehensive Scanning: Run all tools in sequence

- **Dual Interface**:
  - Modern GUI interface with real-time scan results
  - Traditional CLI interface for automation and scripting
  - Save results in JSON or CSV formats

- **Advanced Features**:
  - Asynchronous scanning for improved performance
  - Configurable scan parameters
  - Geolocation data for targets
  - Rate limiting to prevent network overload

## Installation

### Using Docker (Recommended)

```bash
# Build the Docker image
docker build -t netrecon-pro .

# Run the GUI version
docker run -it --rm \
    -e DISPLAY=$DISPLAY \
    -v /tmp/.X11-unix:/tmp/.X11-unix \
    -v $(pwd)/results:/app/results \
    netrecon-pro

# Run the CLI version
docker run -it --rm \
    -v $(pwd)/results:/app/results \
    netrecon-pro netrecon.py [options]
```

### Manual Installation

1. Install system dependencies:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap traceroute netcat openssl python3-tk
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### GUI Mode

1. Start the GUI:
   ```bash
   python gui.py
   ```

2. Enter your target (IP address or domain)
3. Optionally specify ports to scan
4. Click on any scan button to start the analysis

### CLI Mode

```bash
python netrecon.py [target] [options]
```

Options:
- `-p, --ports`: Specify ports to scan (e.g., '80,443' or '1-1024')
- `-o, --output`: Output format (json or csv)

Example:
```bash
python netrecon.py example.com -p 80,443 -o json
```

## Configuration

Edit `config.yaml` to customize:
- Scan timeout values
- Thread limits
- Default ports
- Geolocation provider

## Security Considerations

- Ensure you have permission to scan target networks
- Use rate limiting to prevent network disruption
- Follow responsible disclosure practices
- Avoid aggressive scanning on production systems
