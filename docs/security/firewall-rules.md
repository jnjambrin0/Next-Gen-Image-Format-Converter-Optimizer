# Firewall Configuration for Network Isolation

This guide provides firewall rules to ensure the Image Converter application operates in complete network isolation. These rules block all outbound connections while allowing the application to function locally.

## Table of Contents

- [Overview](#overview)
- [Linux (iptables)](#linux-iptables)
- [Linux (nftables)](#linux-nftables)
- [Windows Firewall](#windows-firewall)
- [macOS (pf)](#macos-pf)
- [Docker Configuration](#docker-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Overview

The Image Converter is designed to operate completely offline. These firewall rules provide an additional layer of security by blocking any potential network connections at the OS level.

### Key Principles

1. **Block all outbound connections** from the application
2. **Allow localhost-only connections** for API communication
3. **No inbound connections** from external sources
4. **No DNS resolution** permitted

## Linux (iptables)

### Basic Rules

```bash
#!/bin/bash
# Image Converter Network Isolation Rules for iptables

# Create a new chain for the image converter
sudo iptables -N IMAGE_CONVERTER 2>/dev/null || true

# Mark packets from the image converter process (assuming it runs as a specific user)
# Replace 'imageconv' with actual username if different
sudo iptables -A OUTPUT -m owner --uid-owner imageconv -j IMAGE_CONVERTER

# Allow localhost connections only
sudo iptables -A IMAGE_CONVERTER -o lo -j ACCEPT

# Block all other outbound connections
sudo iptables -A IMAGE_CONVERTER -j REJECT --reject-with icmp-host-prohibited

# Block DNS queries specifically
sudo iptables -A IMAGE_CONVERTER -p udp --dport 53 -j DROP
sudo iptables -A IMAGE_CONVERTER -p tcp --dport 53 -j DROP

# Log blocked attempts (optional)
sudo iptables -A IMAGE_CONVERTER -j LOG --log-prefix "IMAGE_CONVERTER_BLOCKED: " --log-level 4

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### Process-Based Rules

```bash
# Alternative: Block by process name using xt_owner module
sudo iptables -A OUTPUT -m owner --cmd-owner python3 -d ! 127.0.0.0/8 -j REJECT
sudo iptables -A OUTPUT -m owner --cmd-owner uvicorn -d ! 127.0.0.0/8 -j REJECT
```

### Remove Rules

```bash
# Remove image converter rules
sudo iptables -F IMAGE_CONVERTER
sudo iptables -X IMAGE_CONVERTER
sudo iptables -D OUTPUT -m owner --uid-owner imageconv -j IMAGE_CONVERTER
```

## Linux (nftables)

### NFTables Rules (Modern Linux)

```bash
#!/usr/sbin/nft -f
# Image Converter Network Isolation Rules for nftables

# Create table and chain
table inet image_converter {
    chain output {
        type filter hook output priority 0; policy accept;
        
        # Match by user ID (replace 1001 with actual UID)
        meta skuid 1001 jump isolate_app
        
        # Or match by process name
        meta skuid { "python3", "uvicorn" } ip daddr != 127.0.0.0/8 drop
    }
    
    chain isolate_app {
        # Allow localhost
        oif "lo" accept
        
        # Block everything else
        counter drop
    }
}
```

### Apply NFTables Rules

```bash
# Load rules
sudo nft -f /etc/nftables/image-converter.nft

# List rules
sudo nft list table inet image_converter
```

## Windows Firewall

### PowerShell Commands

```powershell
# Image Converter Network Isolation Rules for Windows Firewall

# Block all outbound connections for the application
New-NetFirewallRule -DisplayName "Block Image Converter Outbound" `
    -Direction Outbound `
    -Program "C:\Program Files\ImageConverter\python.exe" `
    -Action Block `
    -Profile Any

# Allow localhost only
New-NetFirewallRule -DisplayName "Allow Image Converter Localhost" `
    -Direction Outbound `
    -Program "C:\Program Files\ImageConverter\python.exe" `
    -RemoteAddress "127.0.0.1", "::1" `
    -Action Allow `
    -Profile Any

# Block DNS specifically
New-NetFirewallRule -DisplayName "Block Image Converter DNS" `
    -Direction Outbound `
    -Program "C:\Program Files\ImageConverter\python.exe" `
    -Protocol UDP `
    -RemotePort 53 `
    -Action Block

# Block all inbound to the app
New-NetFirewallRule -DisplayName "Block Image Converter Inbound" `
    -Direction Inbound `
    -Program "C:\Program Files\ImageConverter\python.exe" `
    -Action Block `
    -Profile Any
```

### GUI Configuration

1. Open Windows Defender Firewall with Advanced Security
2. Create new Outbound Rule:
   - Program: Path to python.exe
   - Action: Block the connection
   - Profile: All profiles
3. Create exception for localhost:
   - Same program path
   - Action: Allow
   - Scope: Remote IP addresses: 127.0.0.1, ::1

### Remove Rules

```powershell
# Remove firewall rules
Remove-NetFirewallRule -DisplayName "Block Image Converter*"
Remove-NetFirewallRule -DisplayName "Allow Image Converter*"
```

## macOS (pf)

### PF Configuration

Create `/etc/pf.anchors/com.imageconverter`:

```bash
# Image Converter Network Isolation Rules for macOS pf

# Define the application (by user ID - replace 501 with actual UID)
image_converter_uid = "501"

# Block all outbound traffic from the app except localhost
block out quick proto { tcp, udp } from any to ! 127.0.0.0/8 user $image_converter_uid
block out quick proto { tcp, udp } from any to ! ::1 user $image_converter_uid

# Specifically block DNS
block out quick proto udp from any to any port 53 user $image_converter_uid
block out quick proto tcp from any to any port 53 user $image_converter_uid

# Log blocked attempts (optional)
block out log quick from any to any user $image_converter_uid
```

### Enable PF Rules

```bash
# Load anchor into main ruleset
echo 'anchor "com.imageconverter"' | sudo tee -a /etc/pf.conf
echo 'load anchor "com.imageconverter" from "/etc/pf.anchors/com.imageconverter"' | sudo tee -a /etc/pf.conf

# Enable pf
sudo pfctl -e

# Load rules
sudo pfctl -f /etc/pf.conf
```

### Application Firewall

Additionally, use macOS Application Firewall:

```bash
# Block all incoming connections
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on

# Add specific app blocking
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/ImageConverter.app
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --block /path/to/ImageConverter.app
```

## Docker Configuration

### Docker Network Isolation

```yaml
# docker-compose.yml with network isolation
version: '3.8'

services:
  image-converter:
    image: image-converter:latest
    # No network access
    network_mode: none
    # Or use internal network only
    networks:
      - isolated
    # Drop all capabilities
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    
networks:
  isolated:
    internal: true  # No external connectivity
```

### Docker Run Command

```bash
# Run with complete network isolation
docker run --network=none \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  image-converter:latest

# Or with localhost only
docker run --network=host \
  --add-host=example.com:127.0.0.1 \
  --dns=127.0.0.1 \
  image-converter:latest
```

## Verification

### Test Network Isolation

```bash
# 1. Check if rules are active
# Linux
sudo iptables -L IMAGE_CONVERTER -n -v
sudo nft list table inet image_converter

# macOS
sudo pfctl -sr | grep imageconverter

# Windows PowerShell
Get-NetFirewallRule -DisplayName "*Image Converter*"

# 2. Test from within application
# This should fail if properly isolated
curl https://www.google.com
ping 8.8.8.8
nslookup example.com

# 3. Monitor blocked attempts
# Linux
sudo tail -f /var/log/syslog | grep IMAGE_CONVERTER_BLOCKED

# macOS
sudo tail -f /var/log/pffirewall.log

# Windows Event Viewer
# Check Windows Firewall logs
```

### Automated Testing Script

```bash
#!/bin/bash
# test-network-isolation.sh

echo "Testing Image Converter Network Isolation..."

# Test DNS resolution (should fail)
if python3 -c "import socket; socket.getaddrinfo('google.com', 80)" 2>/dev/null; then
    echo "❌ FAIL: DNS resolution succeeded"
    exit 1
else
    echo "✅ PASS: DNS resolution blocked"
fi

# Test outbound connection (should fail)
if curl -s --max-time 2 https://www.google.com >/dev/null 2>&1; then
    echo "❌ FAIL: Outbound connection succeeded"
    exit 1
else
    echo "✅ PASS: Outbound connections blocked"
fi

# Test localhost (should succeed)
if curl -s --max-time 2 http://localhost:8080/api/health >/dev/null 2>&1; then
    echo "✅ PASS: Localhost connections allowed"
else
    echo "❌ FAIL: Localhost connections blocked"
    exit 1
fi

echo "✅ All network isolation tests passed!"
```

## Troubleshooting

### Common Issues

1. **Application won't start**
   - Ensure localhost connections are allowed
   - Check if the application user/process is correctly identified

2. **Firewall rules not persisting**
   - Linux: Use `iptables-persistent` package
   - macOS: Add rules to `/etc/pf.conf`
   - Windows: Rules persist by default

3. **Rules blocking too much**
   - Ensure loopback interface is excluded
   - Check rule ordering (allow rules before block rules)

### Debug Commands

```bash
# Watch network connections in real-time
# Linux
watch -n 1 'ss -tunap | grep python'

# macOS
sudo lsof -i -n | grep Python

# Windows PowerShell
Get-NetTCPConnection | Where {$_.OwningProcess -eq (Get-Process python).Id}

# Monitor firewall logs
# Linux
journalctl -f | grep -i firewall

# macOS
log stream --predicate 'process == "pf"'
```

### Emergency Disable

If rules cause issues, disable them:

```bash
# Linux
sudo iptables -F IMAGE_CONVERTER
sudo iptables -X IMAGE_CONVERTER

# macOS
sudo pfctl -d

# Windows PowerShell
Disable-NetFirewallRule -DisplayName "*Image Converter*"
```

## Best Practices

1. **Test thoroughly** before deploying to production
2. **Monitor logs** for blocked connection attempts
3. **Use process-based rules** rather than port-based when possible
4. **Implement multiple layers** (application + OS firewall)
5. **Document any exceptions** clearly
6. **Regular audits** to ensure rules are still effective

## Additional Resources

- [iptables documentation](https://netfilter.org/documentation/)
- [nftables wiki](https://wiki.nftables.org/)
- [Windows Firewall documentation](https://docs.microsoft.com/windows/security/threat-protection/windows-firewall/)
- [macOS pf documentation](https://www.openbsd.org/faq/pf/)
- [Docker security best practices](https://docs.docker.com/engine/security/)