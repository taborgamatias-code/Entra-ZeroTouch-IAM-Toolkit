#!/bin/bash
# ==============================================================================
# Script Name: macos-vip-endpoint-triage.sh
# Description: Rapid Tier-2 / Executive Support Diagnostic & Security Triage
#              Collects FileVault encryption state, MDM enrollment profile health,
#              network/DNS latency, and resource bottlenecks for ServiceNow/Jira tickets.
# Author:      Andres Taborga
# ==============================================================================

BOLD="\033[1m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}================================================================${RESET}"
echo -e "${CYAN}${BOLD}   EXECUTIVE ENDPOINT DIAGNOSTIC & SECURITY TRIAGE (macOS)      ${RESET}"
echo -e "${CYAN}${BOLD}================================================================${RESET}"
echo -e "Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo -e "Hostname:  $(scutil --get LocalHostName 2>/dev/null || hostname)"
echo -e "OS Build:  $(sw_vers -productName) $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
echo -e "Uptime:    $(uptime | awk -F'( |,|:)+' '{print $6,$7",",$8,"hours,",$9,"minutes"}')\n"

# 1. Hardware & Storage Health
echo -e "${YELLOW}[1/5] Hardware & APFS Storage Telemetry${RESET}"
FREE_STORAGE=$(df -h / | awk 'NR==2 {print $4 " free of " $2 " (" $5 " used)"}')
echo -e "  -> Root Volume Capacity: ${GREEN}${FREE_STORAGE}${RESET}"

# 2. Security Posture: FileVault, SIP & Gatekeeper
echo -e "\n${YELLOW}[2/5] Endpoint Security & Encryption Posture${RESET}"
FV_STATUS=$(fdesetup status)
if [[ "$FV_STATUS" == *"FileVault is On"* ]]; then
    echo -e "  -> FileVault Disk Encryption: ${GREEN}ENABLED (Compliant)${RESET}"
else
    echo -e "  -> FileVault Disk Encryption: ${RED}DISABLED (NON-COMPLIANT)${RESET}"
fi

SIP_STATUS=$(csrutil status)
echo -e "  -> System Integrity (SIP):    ${SIP_STATUS}"
GK_STATUS=$(spctl --status)
echo -e "  -> Gatekeeper Status:         ${GK_STATUS}"

# 3. MDM / Jamf Enrollment Verification
echo -e "\n${YELLOW}[3/5] Enterprise MDM Enrollment State${RESET}"
MDM_PROFILES=$(profiles status -type enrollment 2>/dev/null)
if [[ -n "$MDM_PROFILES" ]]; then
    echo "$MDM_PROFILES" | sed 's/^/  -> /'
else
    echo -e "  -> MDM Status: Standard Local Account / Unenrolled"
fi

# 4. Network, VPN & DNS Resolution Speed
echo -e "\n${YELLOW}[4/5] Network & Enterprise Connectivity Triage${RESET}"
PRIMARY_IF=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
LOCAL_IP=$(ipconfig getifaddr "$PRIMARY_IF" 2>/dev/null || echo "Disconnected")
DNS_SERVERS=$(scutil --dns | grep 'nameserver\[[0-9]*\]' | awk '{print $3}' | sort -u | tr '\n' ' ')
PING_LATENCY=$(ping -c 2 -W 1000 1.1.1.1 2>/dev/null | tail -1 | awk -F '/' '{print $5 " ms"}')

echo -e "  -> Active Interface:  ${PRIMARY_IF:-None} (IP: ${LOCAL_IP})"
echo -e "  -> Configured DNS:    ${DNS_SERVERS}"
echo -e "  -> Gateway Latency:   ${GREEN}${PING_LATENCY:-Timeout}${RESET}"

# 5. Top CPU/Memory Consumers (Identify runaway processes)
echo -e "\n${YELLOW}[5/5] Top 5 Resource-Intensive Processes (CPU/MEM)${RESET}"
ps -Ao comm,pcpu,pmem -r | head -n 6 | awk '{printf "  -> %-35s CPU: %5s%%   MEM: %5s%%\n", $1, $2, $3}'

echo -e "\n${CYAN}${BOLD}================================================================${RESET}"
echo -e "${GREEN}Triage Complete. Ready for ServiceNow / Jira ticket attachment.${RESET}"
echo -e "${CYAN}${BOLD}================================================================${RESET}"
