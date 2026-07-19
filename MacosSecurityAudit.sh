#!/usr/bin/env bash

# ==========================================================
# macOS Security Audit
# Version : 0.5
# Author  : Sergey A. Martynov
# License : MIT
# ==========================================================

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
BOLD="\033[1m"
RESET="\033[0m"

PASS=0
WARN=0
FAIL=0

LOG_FILE="$HOME/Desktop/macOS_security_audit_$(date +"%Y%m%d_%H%M%S").log"

exec > >(tee -a "$LOG_FILE") 2>&1


pass() {
    ((PASS++))
    echo -e "${GREEN}[PASS]${RESET} $1"
}

warn() {
    ((WARN++))
    echo -e "${YELLOW}[WARN]${RESET} $1"
}

fail() {
    ((FAIL++))
    echo -e "${RED}[FAIL]${RESET} $1"
}

info() {
    echo -e "${CYAN}[INFO]${RESET} $1"
}

section() {
    echo
    echo -e "${BLUE}${BOLD}====================================================${RESET}"
    echo -e "${BLUE}${BOLD}$1${RESET}"
    echo -e "${BLUE}${BOLD}====================================================${RESET}"
}


clear

echo -e "${BOLD}"
echo "        🍎 macOS Security Audit v0.5"
echo "        ---------------------------"
echo
echo "        Audit log:"
echo "        $LOG_FILE"
echo -e "${RESET}"


#############################################
section "System Information"

info "Computer Name : $(scutil --get ComputerName)"
info "Hostname      : $(hostname)"
info "macOS Version : $(sw_vers -productVersion)"
info "Build         : $(sw_vers -buildVersion)"
info "Architecture  : $(uname -m)"
info "Kernel        : $(uname -r)"


#############################################
section "System Integrity Protection"

if csrutil status 2>/dev/null | grep -qi enabled; then
    pass "System Integrity Protection is enabled."
else
    fail "System Integrity Protection is disabled."
fi


#############################################
section "Gatekeeper"

if spctl --status 2>/dev/null | grep -qi enabled; then
    pass "Gatekeeper is enabled."
else
    fail "Gatekeeper is disabled."
fi


#############################################
section "FileVault"

fv=$(fdesetup status 2>/dev/null)

if echo "$fv" | grep -qi "On"; then
    pass "FileVault is enabled."

    fv_progress=$(diskutil apfs listCryptoUsers / 2>/dev/null)

    if [[ -n "$fv_progress" ]]; then
        info "Encryption information available."
    fi

else
    warn "FileVault is disabled."
fi


#############################################
section "Firewall"

firewall=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)

if echo "$firewall" | grep -qi "enabled"; then
    pass "macOS Application Firewall is enabled."
else
    warn "macOS Application Firewall is disabled."
fi


#############################################
section "Remote Login (SSH)"

ssh_status=$(systemsetup -getremotelogin 2>/dev/null)

if echo "$ssh_status" | grep -qi "On"; then
    warn "Remote Login (SSH) is enabled."
else
    pass "Remote Login (SSH) is disabled."
fi


#############################################
section "Automatic Updates"

update_config=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>/dev/null)


if echo "$update_config" | grep -q "AutomaticDownload = 1"; then
    pass "Automatic update downloads are enabled."
else
    warn "Automatic update downloads are disabled."
fi


if echo "$update_config" | grep -q "AutomaticallyInstallMacOSUpdates = 1"; then
    pass "Automatic macOS updates installation is enabled."
else
    warn "Automatic macOS updates installation is disabled."
fi


if echo "$update_config" | grep -q "CriticalUpdateInstall = 1"; then
    pass "Critical security updates installation is enabled."
else
    warn "Critical security updates installation is disabled."
fi


#############################################
section "Pending Updates"

updates=$(softwareupdate -l 2>&1)

if echo "$updates" | grep -q "No new software available"; then
    pass "System is fully up to date."
else
    warn "Updates are available."
fi


#############################################
section "Secure Boot"

secure_boot=$(system_profiler SPiBridgeDataType 2>/dev/null | grep "Secure Boot")

if [[ -n "$secure_boot" ]]; then
    info "$secure_boot"
else
    info "Secure Boot information unavailable."
fi


#############################################
section "Rosetta 2"

if /usr/bin/pgrep oahd >/dev/null 2>&1; then
    info "Rosetta 2 is installed and active."
else

    if /usr/bin/arch -x86_64 /usr/bin/true 2>/dev/null; then
        info "Rosetta 2 is installed."
    else
        info "Rosetta 2 is not installed."
    fi

fi
#############################################
section "Find My Mac"

find_my=$(defaults read /Library/Preferences/com.apple.findmy.findmymac 2>/dev/null)

if [[ -n "$find_my" ]]; then
    info "Find My Mac configuration detected."
else
    info "Find My Mac status unavailable."
fi


#############################################
section "Homebrew"

if command -v brew >/dev/null 2>&1; then

    pass "Homebrew is installed."

    formula_count=$(brew list --formula 2>/dev/null | wc -l | tr -d ' ')
    cask_count=$(brew list --cask 2>/dev/null | wc -l | tr -d ' ')

    info "Formulae : $formula_count"
    info "Casks    : $cask_count"

else

    info "Homebrew is not installed."

fi


#############################################
section "Administrator Users"

admins=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null)

if [[ -n "$admins" ]]; then
    info "$admins"
else
    info "Unable to read administrator group."
fi


#############################################
section "Launch Agents"

user_agents=$(find ~/Library/LaunchAgents \
    -maxdepth 1 \
    -name "*.plist" \
    2>/dev/null)

system_agents=$(find /Library/LaunchAgents \
    -maxdepth 1 \
    -name "*.plist" \
    2>/dev/null)


agent_count=$(echo "$user_agents $system_agents" | wc -w | tr -d ' ')

info "Launch Agents found: $agent_count"


if [[ "$agent_count" -gt 0 ]]; then

    echo
    echo "User/System Launch Agents:"

    echo "$user_agents"
    echo "$system_agents"

fi


#############################################
section "Listening Ports"

ports=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null)

port_count=$(echo "$ports" | tail -n +2 | wc -l | tr -d ' ')


info "Listening TCP ports: $port_count"


if [[ "$port_count" -gt 0 ]]; then

    echo
    echo "$ports"

fi


#############################################
section "Running Security Related Services"


services=$(ps aux | grep -Ei \
"ssh|vpn|docker|firewall|security|xpc|endpoint" \
| grep -v grep)


if [[ -n "$services" ]]; then

    info "Relevant services detected:"
    echo "$services"

else

    info "No additional security related services detected."

fi


#############################################
section "Summary"


echo

echo "Passed   : $PASS"
echo "Warnings : $WARN"
echo "Failed   : $FAIL"


score=100

((score -= WARN*10))
((score -= FAIL*25))

(( score < 0 )) && score=0


echo
echo "Security Score: ${score}/100"


if (( FAIL > 0 )); then

    echo -e "${RED}[FAIL] Security posture requires attention.${RESET}"

elif (( WARN > 0 )); then

    echo -e "${YELLOW}[WARN] Security posture is good but can be improved.${RESET}"

else

    echo -e "${GREEN}[PASS] Security posture looks excellent.${RESET}"

fi



#############################################
section "Security Recommendations"


if ! echo "$firewall" | grep -qi "enabled"; then

    echo "[1] Enable macOS Application Firewall:"
    echo "    System Settings → Network → Firewall"
    echo

fi


if ! echo "$update_config" | grep -q "AutomaticDownload = 1"; then

    echo "[2] Enable automatic update downloads."
    echo

fi


if [[ "$port_count" -gt 15 ]]; then

    echo "[3] Review listening network services:"
    echo "    Many TCP ports are open."
    echo

fi


if (( WARN == 0 && FAIL == 0 )); then

    echo "No recommendations. System configuration looks strong."

fi


echo
echo "Audit completed."
echo "Report saved:"
echo "$LOG_FILE"