# NetRecon Pro

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker Ready](https://img.shields.io/badge/docker-ready-blue)

Advanced network reconnaissance tool with:
- Async IP/port scanning
- Multi-source geolocation
- Configurable scanning profiles
- JSON/CSV export

## Features

- IPv4/IPv6 support
- Rate-limited scanning
- MaxMind + IP-API geolocation
- Docker container support
- Configurable via YAML

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Basic scan
python netrecon.py 192.168.1.0/24 -p 1-1024 -o json

# Docker
docker build -t netrecon .
docker run -it netrecon 8.8.8.8
