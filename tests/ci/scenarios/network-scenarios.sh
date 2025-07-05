#!/bin/bash
set -euo pipefail

# Network Connection Test Scenarios
# Tests various network patterns to verify detection

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

CONTAINER_NAME="${1:-bee-trace-test}"
RESULTS_FILE="${2:-${SCRIPT_DIR}/../results/network-monitor-results.json}"
LOG_FILE="${SCRIPT_DIR}/../results/bee-trace.log"

# Test: Suspicious Port Connections
test_suspicious_ports() {
    log_info "Testing suspicious port connection detection..."
    
    # Common malware/backdoor ports
    generate_network_connection "127.0.0.1" "4444"    # Metasploit default
    generate_network_connection "127.0.0.1" "6667"    # IRC
    generate_network_connection "127.0.0.1" "31337"   # Elite/backdoor
    generate_network_connection "127.0.0.1" "1337"    # Common backdoor
    generate_network_connection "127.0.0.1" "8545"    # Ethereum RPC
    
    sleep 2
    
    # Verify detection
    if wait_for_event "${LOG_FILE}" "TCP_CONNECT.*port=4444\|port=6667" 5 "Suspicious port connections"; then
        return 0
    else
        return 1
    fi
}

# Test: Crypto Mining Pools
test_mining_pool_connections() {
    log_info "Testing crypto mining pool detection..."
    
    # Known mining pool IPs (using local IPs for testing)
    generate_network_connection "192.168.1.100" "3333"   # Stratum mining
    generate_network_connection "192.168.1.101" "9999"   # Mining pool
    generate_network_connection "10.0.0.50" "14444"      # Monero mining
    
    sleep 2
    
    # Verify detection
    if wait_for_event "${LOG_FILE}" "TCP_CONNECT.*port=3333\|port=9999\|port=14444" 5 "Mining pool connections"; then
        return 0
    else
        return 1
    fi
}

# Test: DNS Exfiltration Pattern
test_dns_exfiltration() {
    log_info "Testing DNS exfiltration pattern detection..."
    
    # Multiple DNS queries (simulated via UDP)
    for i in {1..10}; do
        # Use dig or nslookup if available, otherwise netcat
        if command -v dig >/dev/null 2>&1; then
            timeout 1s dig "data${i}.suspicious.local" @8.8.8.8 >/dev/null 2>&1 || true
        else
            generate_network_connection "8.8.8.8" "53"
        fi
    done
    
    sleep 2
    
    # Check for DNS activity
    if wait_for_event "${LOG_FILE}" "UDP_SEND.*port=53" 5 "DNS activity"; then
        return 0
    else
        return 1
    fi
}

# Test: Rapid Connection Attempts
test_rapid_connections() {
    log_info "Testing rapid connection pattern detection..."
    
    # Generate burst of connections
    for i in {1..20}; do
        generate_network_connection "192.168.1.$((i+10))" "80"
        generate_network_connection "10.0.0.$((i+10))" "443"
    done
    
    sleep 3
    
    # Check for multiple events
    local event_count=$(grep -c "TCP_CONNECT" "${LOG_FILE}" || echo "0")
    if [ "${event_count}" -ge 15 ]; then
        return 0
    else
        echo "Expected at least 15 events, found ${event_count}"
        return 1
    fi
}

# Test: External C2 Simulation
test_c2_connections() {
    log_info "Testing C2 server connection patterns..."
    
    # Simulate C2 communication patterns
    generate_network_connection "185.199.108.153" "443"  # GitHub IP for testing
    sleep 1
    generate_network_connection "185.199.108.153" "443"  # Repeated connection
    sleep 2
    generate_network_connection "185.199.108.153" "443"  # Beacon pattern
    
    # Non-standard HTTPS
    generate_network_connection "192.168.100.50" "8443"
    generate_network_connection "192.168.100.50" "9443"
    
    sleep 2
    
    # Verify detection
    if wait_for_event "${LOG_FILE}" "TCP_CONNECT.*185\.199\|port=8443" 5 "C2 connections"; then
        return 0
    else
        return 1
    fi
}

# Test: Data Exfiltration Ports
test_exfiltration_ports() {
    log_info "Testing data exfiltration port detection..."
    
    # Common exfiltration ports
    generate_network_connection "203.0.113.10" "21"     # FTP
    generate_network_connection "203.0.113.11" "22"     # SSH/SCP
    generate_network_connection "203.0.113.12" "445"    # SMB
    generate_network_connection "203.0.113.13" "3389"   # RDP
    
    sleep 2
    
    # Verify detection
    if wait_for_event "${LOG_FILE}" "TCP_CONNECT.*port=21\|port=22\|port=445" 5 "Exfiltration ports"; then
        return 0
    else
        return 1
    fi
}

# Test: Localhost Connections (Lateral Movement)
test_localhost_connections() {
    log_info "Testing localhost connection detection..."
    
    # Various localhost connections
    generate_network_connection "127.0.0.1" "5432"    # PostgreSQL
    generate_network_connection "127.0.0.1" "3306"    # MySQL
    generate_network_connection "127.0.0.1" "6379"    # Redis
    generate_network_connection "::1" "8080"          # IPv6 localhost
    
    sleep 2
    
    # Verify detection
    if wait_for_event "${LOG_FILE}" "TCP_CONNECT.*127\.0\.0\.1\|::1" 5 "Localhost connections"; then
        return 0
    else
        return 1
    fi
}

# Test: UDP Suspicious Traffic
test_udp_suspicious() {
    log_info "Testing suspicious UDP traffic detection..."
    
    # Generate UDP traffic to suspicious ports
    echo "test" | nc -u 192.168.1.100 1234 2>/dev/null || true
    echo "test" | nc -u 10.0.0.100 5060 2>/dev/null || true     # SIP
    echo "test" | nc -u 172.16.0.100 69 2>/dev/null || true      # TFTP
    
    sleep 2
    
    # Verify detection
    if wait_for_event "${LOG_FILE}" "UDP_SEND" 5 "UDP traffic"; then
        return 0
    else
        return 1
    fi
}

# Test: Port Scanning Pattern
test_port_scanning() {
    log_info "Testing port scanning pattern detection..."
    
    # Sequential port scan simulation
    local target="192.168.1.50"
    for port in {20..30}; do
        generate_network_connection "${target}" "${port}"
    done
    
    # Random port scan
    for _ in {1..10}; do
        local port=$((RANDOM % 1000 + 1024))
        generate_network_connection "10.0.0.100" "${port}"
    done
    
    sleep 3
    
    # Check for scan pattern
    local scan_events=$(grep -c "TCP_CONNECT.*192\.168\.1\.50" "${LOG_FILE}" || echo "0")
    if [ "${scan_events}" -ge 8 ]; then
        return 0
    else
        echo "Expected at least 8 scan events, found ${scan_events}"
        return 1
    fi
}

# Test: Normal Traffic (Negative Test)
test_normal_traffic() {
    log_info "Testing normal traffic filtering..."
    
    # Clear log marker
    echo "=== NORMAL TRAFFIC TEST START ===" >> "${LOG_FILE}"
    
    # Generate normal traffic patterns
    generate_network_connection "8.8.8.8" "53"        # DNS to Google
    generate_network_connection "1.1.1.1" "53"        # DNS to Cloudflare
    generate_network_connection "github.com" "443"    # HTTPS to GitHub
    
    sleep 2
    
    # These should be logged but check they're not flagged as highly suspicious
    # (This is more about ensuring the system doesn't crash on normal traffic)
    local events=$(sed -n '/=== NORMAL TRAFFIC TEST START ===/,$p' "${LOG_FILE}" | grep -c "TCP_CONNECT\|UDP_SEND" || echo "0")
    
    if [ "${events}" -ge 1 ]; then
        return 0
    else
        echo "Normal traffic should still be logged"
        return 1
    fi
}

# Main execution
main() {
    log_info "Starting network connection test scenarios..."
    
    # Check if we have network utilities
    if ! command -v nc >/dev/null 2>&1; then
        log_warning "netcat (nc) not found, some tests may be limited"
    fi
    
    # Run all tests
    run_test "Suspicious Port Connections" test_suspicious_ports "${RESULTS_FILE}"
    run_test "Mining Pool Connections" test_mining_pool_connections "${RESULTS_FILE}"
    run_test "DNS Exfiltration Pattern" test_dns_exfiltration "${RESULTS_FILE}"
    run_test "Rapid Connection Attempts" test_rapid_connections "${RESULTS_FILE}"
    run_test "C2 Server Patterns" test_c2_connections "${RESULTS_FILE}"
    run_test "Data Exfiltration Ports" test_exfiltration_ports "${RESULTS_FILE}"
    run_test "Localhost Connections" test_localhost_connections "${RESULTS_FILE}"
    run_test "UDP Suspicious Traffic" test_udp_suspicious "${RESULTS_FILE}"
    run_test "Port Scanning Pattern" test_port_scanning "${RESULTS_FILE}"
    run_test "Normal Traffic Handling" test_normal_traffic "${RESULTS_FILE}"
    
    log_info "Network connection scenarios completed"
}

main "$@"