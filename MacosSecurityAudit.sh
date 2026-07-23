#!/usr/bin/env bash
# macOS Nightwatch Audit Snapshot 3.2.2
# Heuristic workstation posture analyzer for macOS
# Not EDR, not forensic evidence, not compliance validation.

set -u

G="\033[0;32m"; Y="\033[1;33m"; R="\033[0;31m"; C="\033[0;36m"; B="\033[0;34m"; X="\033[0m"

PASS=0
WARN=0
FAIL=0
NOTICE=0

CORE=100
NET=100
PRIV=100
PERSIST=100
SIGNING=100
ATTACK=100

REVIEW_ITEMS=()
VISIBILITY_GAPS=()
REMEDIATIONS=()
BASELINE_DIFFS=()

OP_PENALTY=0
CONFIDENCE_TOTAL=0
CONFIDENCE_COUNT=0

ID="MSA-$(date +%Y%m%d-%H%M%S)"
VERSION="3.2.2"
DIR="$HOME/Desktop/Nightwatch_$ID"
mkdir -p "$DIR"
LOG="$DIR/audit.log"
JSON="$DIR/report.json"
HTML="$DIR/report.html"
BASE="$HOME/.nightwatch_baseline"
BASE_DETAILS="$HOME/.nightwatch_baseline_details"
ACCEPT_BASELINE=0
QUIET=0
JSON_ONLY=0
OUTPUT_DIR=""

for arg in "$@"; do
  case "$arg" in
    --accept-baseline) ACCEPT_BASELINE=1 ;;
    --quiet) QUIET=1 ;;
    --json-only) JSON_ONLY=1; QUIET=1 ;;
    --output-dir=*) OUTPUT_DIR="${arg#*=}" ;;
    *) ;;
  esac
done

if [ -n "$OUTPUT_DIR" ]; then
  DIR="$OUTPUT_DIR/Nightwatch_$ID"
  mkdir -p "$DIR"
  LOG="$DIR/audit.log"
  JSON="$DIR/report.json"
  HTML="$DIR/report.html"
fi

exec > >(tee -a "$LOG") 2>&1

ok(){ PASS=$((PASS+1)); [ "$QUIET" -eq 0 ] && echo -e "${G}✓ PASS${X} $1"; }
warn(){ WARN=$((WARN+1)); NOTICE=$((NOTICE+1)); [ "$QUIET" -eq 0 ] && echo -e "${Y}⚠ NOTICE${X} $1"; }
fail(){ FAIL=$((FAIL+1)); [ "$QUIET" -eq 0 ] && echo -e "${R}✗ ALERT${X} $1"; }
info(){ [ "$QUIET" -eq 0 ] && echo -e "${C}•${X} $1"; }
section(){ [ "$QUIET" -eq 0 ] && { echo; echo -e "${B}┌─ $1${X}"; }; }
scan(){ [ "$QUIET" -eq 0 ] && echo -e "${C}[+]${X} $1"; }

add_review_item(){ REVIEW_ITEMS+=("$1"); }
add_visibility_gap(){ VISIBILITY_GAPS+=("$1"); }
add_remediation(){ REMEDIATIONS+=("$1"); }
add_baseline_diff(){ BASELINE_DIFFS+=("$1"); }

add_penalty(){
  local points=$1
  OP_PENALTY=$((OP_PENALTY + points))
}

add_confidence(){
  local points=$1
  CONFIDENCE_TOTAL=$((CONFIDENCE_TOTAL + points))
  CONFIDENCE_COUNT=$((CONFIDENCE_COUNT + 1))
}

progress(){
  [ "$QUIET" -eq 1 ] && return 0
  CUR=$1
  TOT=$2
  TXT=$3
  WID=20
  [ "$TOT" -eq 0 ] && TOT=1
  P=$((CUR*WID/TOT))
  printf "\r%s [" "$TXT"
  printf "%${P}s" "" | tr " " "#"
  printf "%$((WID-P))s" "" | tr " " "-"
  printf "] %3d%%" "$((CUR*100/TOT))"
}

json_escape(){
  printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
}

bar(){
  local val=$1 label=$2 filled empty
  filled=$((val/10))
  empty=$((10-filled))
  printf "% -24s " "$label"
  printf "%${filled}s" "" | tr ' ' '█'
  printf "%${empty}s" "" | tr ' ' '░'
  printf " %3s%%\n" "$val"
}

scan_path_dirs(){
  printf "%s\n" "$PATH" | tr ':' '\n' | awk 'NF && !seen[$0]++'
}

join_json_array(){
  local arr_name=$1
  local out=""
  eval "local count=\${#$arr_name[@]}"
  if [ "$count" -gt 0 ]; then
    eval "for item in \"\${$arr_name[@]}\"; do
      item_json=\$(json_escape \"\$item\")
      if [ -n \"\$out\" ]; then
        out=\"\$out, \$item_json\"
      else
        out=\"\$item_json\"
      fi
    done"
  fi
  printf "%s" "$out"
}

render_html_list(){
  local arr_name=$1
  local empty_text=$2
  local out="<ul>"
  eval "local count=\${#$arr_name[@]}"
  if [ "$count" -gt 0 ]; then
    eval "for item in \"\${$arr_name[@]}\"; do
      out=\"\$out<li>\$item</li>\"
    done"
  else
    out="${out}<li>${empty_text}</li>"
  fi
  out="${out}</ul>"
  printf "%s" "$out"
}

severity_from_penalty(){
  local p=$1
  if [ "$p" -ge 5 ]; then
    printf "HIGH"
  elif [ "$p" -ge 2 ]; then
    printf "MODERATE"
  else
    printf "LOW"
  fi
}

confidence_label(){
  local avg=$1
  if [ "$avg" -ge 85 ]; then
    printf "HIGH"
  elif [ "$avg" -ge 65 ]; then
    printf "MEDIUM"
  else
    printf "LOW"
  fi
}

if [ "$JSON_ONLY" -eq 0 ]; then
  clear 2>/dev/null || true
  echo "╔═════════════════════════════════════════════════════╗"
  echo "║       macOS NIGHTWATCH AUDIT SNAPSHOT 3.2.2         ║"
  echo "║        HEURISTIC WORKSTATION POSTURE ANALYZER       ║"
  echo "╚═════════════════════════════════════════════════════╝"
  echo
  echo "INITIALIZING AUDIT"
  for x in Hardware Kernel Privacy Network Persistence; do
    echo "[+] $x layer loaded"
  done
fi

HOST=$(scutil --get ComputerName 2>/dev/null || hostname)
OS=$(sw_vers -productVersion 2>/dev/null || echo unknown)
BUILD=$(sw_vers -buildVersion 2>/dev/null || echo unknown)
ARCH=$(uname -m)
KERNEL=$(uname -r)

HOST_JSON=$(json_escape "$HOST")
OS_JSON=$(json_escape "$OS")
BUILD_JSON=$(json_escape "$BUILD")
ARCH_JSON=$(json_escape "$ARCH")
ID_JSON=$(json_escape "$ID")
VERSION_JSON=$(json_escape "$VERSION")

section "SYSTEM PROFILE"
info "Hostname : $(hostname)"
info "Kernel   : $KERNEL"
info "Machine  : $HOST"
info "macOS    : $OS ($BUILD)"
info "Arch     : $ARCH"
info "Audit ID : $ID"
info "Version  : $VERSION"

section "CORE SECURITY"
scan "SIP"
SIP=$(csrutil status 2>/dev/null || true)
if echo "$SIP" | grep -qi enabled; then
  ok "System Integrity Protection enabled"
  add_confidence 95
else
  fail "System Integrity Protection disabled or unreadable"
  CORE=$((CORE-35))
  add_review_item "System Integrity Protection is disabled or unreadable"
  add_remediation "Check SIP status: csrutil status ; if intentionally disabled, document rationale; if not, re-enable from Recovery OS."
  add_penalty 6
  add_confidence 85
fi

if echo "$SIP" | grep -qi "authenticated root"; then
  ok "Authenticated Root enabled"
  add_confidence 90
else
  info "Authenticated Root status unavailable from csrutil output"
  add_visibility_gap "Authenticated Root status could not be confirmed from csrutil output"
  add_confidence 55
fi

scan "Gatekeeper"
GK_STATE=$(spctl --status 2>/dev/null || true)
if echo "$GK_STATE" | grep -qi enabled; then
  ok "Gatekeeper enabled"
  add_confidence 95
elif [ -n "$GK_STATE" ]; then
  warn "Gatekeeper disabled"
  SIGNING=$((SIGNING-10))
  add_review_item "Gatekeeper is disabled"
  add_remediation "Review Gatekeeper setting: spctl --status ; enable when appropriate: sudo spctl --master-enable"
  add_penalty 2
  add_confidence 90
else
  warn "Gatekeeper status unavailable"
  add_visibility_gap "Gatekeeper status could not be confirmed"
  add_confidence 50
fi

scan "FileVault"
FV_STATE=$(fdesetup status 2>/dev/null || true)
if echo "$FV_STATE" | grep -qi "FileVault is On\|On."; then
  ok "FileVault enabled"
  add_confidence 95
elif [ -n "$FV_STATE" ]; then
  warn "FileVault disabled"
  CORE=$((CORE-20))
  add_review_item "FileVault is disabled"
  add_remediation "Review FileVault: fdesetup status ; enable from System Settings or with fdesetup if appropriate."
  add_penalty 4
  add_confidence 90
else
  warn "FileVault status unavailable"
  CORE=$((CORE-10))
  add_visibility_gap "FileVault status could not be confirmed"
  add_penalty 1
  add_confidence 50
fi

scan "Application Firewall"
FW_STATE=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || true)
if echo "$FW_STATE" | grep -qi enabled; then
  ok "Application Firewall enabled"
  add_confidence 95
elif echo "$FW_STATE" | grep -qi disabled; then
  warn "Application Firewall disabled"
  NET=$((NET-10))
  add_review_item "Application Firewall is disabled"
  add_remediation "Review firewall status: /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate ; enable in System Settings if desired."
  add_penalty 2
  add_confidence 90
else
  warn "Application Firewall status unavailable"
  add_visibility_gap "Application Firewall status could not be confirmed"
  add_confidence 50
fi

scan "Remote Login"
SSH_STATE=$(systemsetup -getremotelogin 2>/dev/null || true)
if echo "$SSH_STATE" | grep -qi on; then
  warn "SSH Remote Login enabled"
  NET=$((NET-15))
  add_review_item "SSH Remote Login is enabled"
  add_remediation "Review remote login: systemsetup -getremotelogin ; disable if unnecessary: sudo systemsetup -setremotelogin off"
  add_penalty 2
  add_confidence 85
elif echo "$SSH_STATE" | grep -qi off; then
  ok "SSH Remote Login disabled"
  add_confidence 85
else
  warn "SSH Remote Login status unavailable"
  add_visibility_gap "SSH Remote Login status could not be confirmed"
  add_confidence 45
fi

section "UPDATE POSTURE"
SU_PREFS=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>/dev/null || true)
echo "$SU_PREFS" | grep -q "AutomaticDownload = 1" && { ok "Automatic downloads enabled"; add_confidence 80; } || { warn "Automatic downloads disabled"; add_confidence 75; }
echo "$SU_PREFS" | grep -q "AutomaticallyInstallMacOSUpdates = 1" && { ok "macOS automatic install enabled"; add_confidence 80; } || { warn "macOS automatic install disabled"; add_confidence 75; }
echo "$SU_PREFS" | grep -q "CriticalUpdateInstall = 1" && { ok "Critical updates enabled"; add_confidence 80; } || { warn "Critical updates disabled"; add_confidence 75; }

section "PATCH STATUS"
SU_LIST=$(softwareupdate -l 2>&1 || true)
if echo "$SU_LIST" | grep -Eq "No new software available|No new software"; then
  ok "softwareupdate reports no pending updates"
  add_confidence 85
else
  warn "Patch status unavailable or pending updates detected"
  add_review_item "Pending updates may exist or patch status could not be confirmed"
  add_remediation "Review available updates with: softwareupdate -l"
  add_penalty 1
  add_confidence 60
fi

section "HARDWARE SECURITY"
if system_profiler SPHardwareDataType 2>/dev/null | grep -qi apple; then
  ok "Apple Silicon detected"
  add_confidence 95
else
  info "Non-Apple-Silicon or unable to confirm architecture"
  add_confidence 80
fi

if ioreg -l 2>/dev/null | grep -qi "AppleSEP\|Secure Enclave"; then
  ok "Secure Enclave detected"
  add_confidence 85
else
  info "Secure Enclave status unavailable from ioreg output"
  add_visibility_gap "Secure Enclave status could not be confirmed from ioreg output"
  add_confidence 50
fi

section "DEVICE MANAGEMENT"
ENROLLMENT=$(profiles status -type enrollment 2>/dev/null || true)
if echo "$ENROLLMENT" | grep -qi "No"; then
  info "MDM enrollment not detected"
  add_confidence 80
else
  info "MDM enrollment present or status unavailable"
  add_confidence 65
fi

section "APPLICATION SIGNING SNAPSHOT"
APPS=$(find /Applications -maxdepth 2 -name "*.app" 2>/dev/null)
TOTAL=$(printf "%s\n" "$APPS" | grep -c ".app" || true)
SIGNED=0
UNSIGNED=0
COUNT=0
NOT_SIGNED=0
LOCAL_MOD=0
OBSOLETE_ENV=0
ARCH_ONLY=0
OTHER_VERIFY=0
NOTARIZED=0
NOT_NOTARIZED=0
NOTARIZATION_UNKNOWN=0

: > "$DIR/unsigned_apps.log"
: > "$DIR/unsigned_apps_detailed.log"
: > "$DIR/notarization.log"

while IFS= read -r APP; do
  [ -z "$APP" ] && continue
  COUNT=$((COUNT+1))
  progress "$COUNT" "$TOTAL" "Checking app signatures"
  if codesign --verify "$APP" >/dev/null 2>&1; then
    SIGNED=$((SIGNED+1))
  else
    UNSIGNED=$((UNSIGNED+1))
    printf "%s\n" "$APP" >> "$DIR/unsigned_apps.log"
    DETAIL=$(codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -n 1)
    [ -z "$DETAIL" ] && DETAIL="verification failed with no detailed message"
    printf "%s :: %s\n" "$APP" "$DETAIL" >> "$DIR/unsigned_apps_detailed.log"
    case "$DETAIL" in
      *"not signed at all"*) NOT_SIGNED=$((NOT_SIGNED+1)) ;;
      *"file modified:"*) LOCAL_MOD=$((LOCAL_MOD+1)) ;;
      *"resource envelope is obsolete"*) OBSOLETE_ENV=$((OBSOLETE_ENV+1)) ;;
      *"In architecture:"*) ARCH_ONLY=$((ARCH_ONLY+1)) ;;
      *) OTHER_VERIFY=$((OTHER_VERIFY+1)) ;;
    esac
  fi

  SPCTL_APP=$(spctl -a -vv "$APP" 2>&1 || true)
  if echo "$SPCTL_APP" | grep -qi "Notarized Developer ID"; then
    NOTARIZED=$((NOTARIZED+1))
    printf "%s :: notarized\n" "$APP" >> "$DIR/notarization.log"
  elif echo "$SPCTL_APP" | grep -qi "source=Developer ID"; then
    NOT_NOTARIZED=$((NOT_NOTARIZED+1))
    printf "%s :: developer-id-no-notarization-confirmation\n" "$APP" >> "$DIR/notarization.log"
  else
    NOTARIZATION_UNKNOWN=$((NOTARIZATION_UNKNOWN+1))
    printf "%s :: unable-to-confirm\n" "$APP" >> "$DIR/notarization.log"
  fi
done <<< "$APPS"

[ "$QUIET" -eq 0 ] && echo
info "Applications scanned                  : $TOTAL"
info "Code-signed applications              : $SIGNED"
info "Unsigned or unverifiable applications : $UNSIGNED"
info "Not signed at all                     : $NOT_SIGNED"
info "Locally modified after install        : $LOCAL_MOD"
info "Obsolete resource envelope            : $OBSOLETE_ENV"
info "Architecture-only verify oddities     : $ARCH_ONLY"
info "Other verify failures                 : $OTHER_VERIFY"
info "Notarized assessments                 : $NOTARIZED"
info "Developer ID without notarization hit : $NOT_NOTARIZED"
info "Notarization unknown                  : $NOTARIZATION_UNKNOWN"

if [ "$UNSIGNED" -gt 0 ]; then
  warn "Application signing posture has review items"
  SIGNING=$((SIGNING-(NOT_SIGNED*8 + LOCAL_MOD*3 + OBSOLETE_ENV*2 + OTHER_VERIFY*4)))
  add_review_item "Application signing review items detected: $UNSIGNED total, including $NOT_SIGNED not signed and $LOCAL_MOD locally modified"
  add_remediation "Review $DIR/unsigned_apps_detailed.log and inspect affected apps with: codesign --verify --deep --strict --verbose=2 \"/path/to/App.app\""
  [ "$NOT_SIGNED" -gt 0 ] && add_penalty 2
  [ "$LOCAL_MOD" -gt 0 ] && add_penalty 1
  [ "$OTHER_VERIFY" -gt 0 ] && add_penalty 1
  add_confidence 80
else
  ok "No unsigned or unverifiable applications found"
  add_confidence 85
fi
[ "$SIGNING" -lt 0 ] && SIGNING=0

if [ "$TOTAL" -gt 0 ]; then
  NOTARIZATION_SCORE=$(((NOTARIZED*100)/TOTAL))
else
  NOTARIZATION_SCORE=0
fi

if [ "$NOT_NOTARIZED" -gt 0 ]; then
  add_review_item "Notarization assessment found Developer ID apps without clear notarization confirmation: $NOT_NOTARIZED"
  add_remediation "Review notarization details in $DIR/notarization.log and validate specific apps with: spctl -a -vv \"/path/to/App.app\""
  add_penalty 1
fi

if [ "$NOTARIZATION_UNKNOWN" -gt $((TOTAL/3 + 1)) ]; then
  add_visibility_gap "Notarization could not be confirmed for a significant subset of applications"
fi

if [ "$NOTARIZATION_SCORE" -ge 80 ]; then
  NOTARIZATION_ASSESSMENT="STRONG"
elif [ "$NOTARIZATION_SCORE" -ge 50 ]; then
  NOTARIZATION_ASSESSMENT="MIXED"
else
  NOTARIZATION_ASSESSMENT="LIMITED"
fi
add_confidence 75

info "Detailed verification failures logged to unsigned_apps_detailed.log"
info "Notarization details logged to notarization.log"
info "Application signing posture is heuristic, especially on developer workstations"

section "SYSTEM EXTENSIONS"
SYSEXT_OUTPUT=$(systemextensionsctl list 2>/dev/null || true)
SYSEXT_ENABLED=$(printf "%s\n" "$SYSEXT_OUTPUT" | grep -ci enabled || true)
if [ "$SYSEXT_ENABLED" -gt 0 ]; then
  info "Enabled system extensions : $SYSEXT_ENABLED"
  add_confidence 75
else
  info "No enabled system extensions detected or status unavailable"
  add_confidence 65
fi

KEXT_OUTPUT=$(kmutil showloaded 2>/dev/null || true)
APPLE_KEXTS=$(printf "%s\n" "$KEXT_OUTPUT" | grep -c "com.apple" || true)
info "Loaded Apple kernel extensions (reported): $APPLE_KEXTS"

section "LOGIN ITEMS SNAPSHOT"
LOGIN_OUTPUT=$(sfltool dumpbtm 2>/dev/null || true)
APPLE_LOGIN=$(printf "%s\n" "$LOGIN_OUTPUT" | grep -c "com.apple" || true)
USER_LOGIN=$(printf "%s\n" "$LOGIN_OUTPUT" | grep -ci "user" || true)
THIRD_LOGIN=$(printf "%s\n" "$LOGIN_OUTPUT" | grep -Ei -c "developer|teamid|bundle identifier" || true)
info "Apple-managed references      : $APPLE_LOGIN"
info "User-related references       : $USER_LOGIN"
info "Third-party metadata entries  : $THIRD_LOGIN"
ok "Login items snapshot collected (heuristic only)"
info "Metadata entries are not equal to suspicious login items"
add_confidence 65

section "NETWORK EXTENSIONS"
if printf "%s\n" "$SYSEXT_OUTPUT" | grep -qi enabled; then
  info "System extension framework active"
  add_confidence 70
else
  info "No enabled system extensions detected"
  add_confidence 60
fi

UTUN_COUNT=$(ifconfig 2>/dev/null | grep -c "^utun" || true)
if [ "$UTUN_COUNT" -gt 0 ]; then
  info "utun interfaces present : $UTUN_COUNT"
else
  info "No utun interfaces detected"
fi
info "Presence of utun interfaces is only a hint, not proof of VPN use"

section "QUARANTINE XATTR SNAPSHOT"
QX_MISSING=0
FILES=0
: > "$DIR/no_quarantine_xattr.log"
TARGETS=$(find "$HOME/Downloads" -type f 2>/dev/null | grep -E '\.(app|pkg|dmg)$' | head -200)
QTOTAL=$(printf "%s\n" "$TARGETS" | grep -c . || true)

while IFS= read -r F; do
  [ -z "$F" ] && continue
  FILES=$((FILES+1))
  progress "$FILES" "$QTOTAL" "Scanning quarantine xattrs"
  if ! xattr "$F" 2>/dev/null | grep -q com.apple.quarantine; then
    QX_MISSING=$((QX_MISSING+1))
    printf "%s\n" "$F" >> "$DIR/no_quarantine_xattr.log"
  fi
done <<< "$TARGETS"

[ "$QUIET" -eq 0 ] && echo
info "Files analysed                  : $FILES"
info "Files without quarantine xattr  : $QX_MISSING"
info "Interpret carefully: missing quarantine metadata is not automatically malicious"

if [ "$FILES" -ge 20 ] && [ "$QX_MISSING" -gt $((FILES*80/100)) ]; then
  warn "High ratio of recent download artifacts without quarantine xattr"
  SIGNING=$((SIGNING-5))
  add_review_item "High ratio of recent download artifacts without quarantine xattr"
  add_remediation "Review recent downloads in $HOME/Downloads and inspect items listed in $DIR/no_quarantine_xattr.log"
  add_penalty 1
  add_confidence 75
else
  ok "No unusual quarantine-xattr ratio detected"
  add_confidence 75
fi
[ "$SIGNING" -lt 0 ] && SIGNING=0

section "PERSISTENCE SNAPSHOT"
UA=$(find "$HOME/Library/LaunchAgents" -type f 2>/dev/null | wc -l | tr -d ' ')
SA=$(find /Library/LaunchAgents -type f 2>/dev/null | wc -l | tr -d ' ')
LD=$(find /Library/LaunchDaemons -type f 2>/dev/null | wc -l | tr -d ' ')

info "User LaunchAgents : $UA"
info "System Agents     : $SA"
info "LaunchDaemons     : $LD"

: > "$DIR/suspicious_persistence.log"
SUSP_PATHS=$(find "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons -type f 2>/dev/null | grep -Ei "miner|keylog|payload|inject|steal|crypt" || true)
SUSP=$(printf "%s\n" "$SUSP_PATHS" | grep -c . || true)

if [ "$SUSP" -eq 0 ]; then
  ok "No obviously suspicious persistence names found"
  add_confidence 70
else
  printf "%s\n" "$SUSP_PATHS" > "$DIR/suspicious_persistence.log"
  warn "Persistence entries with suspicious-looking names detected"
  PERSIST=$((PERSIST-20))
  add_review_item "Persistence entries with suspicious-looking names were detected"
  add_remediation "Review suspicious persistence entries listed in $DIR/suspicious_persistence.log"
  add_penalty 4
  add_confidence 70
fi
info "Persistence name matching is heuristic only"

section "PRIVACY FRAMEWORK"
TCC="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
if [ -f "$TCC" ]; then
  ok "TCC database present"
  add_confidence 85
else
  warn "TCC database not found in user profile"
  PRIV=$((PRIV-15))
  add_review_item "TCC database was not found in the user profile"
  add_remediation "Validate user privacy database presence: ls -l \"$HOME/Library/Application Support/com.apple.TCC/TCC.db\""
  add_penalty 2
  add_confidence 85
fi

ANALYTICS_STATE=$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory AutoSubmit 2>/dev/null || true)
if [ "$ANALYTICS_STATE" = "0" ]; then
  ok "Automatic diagnostic submission appears disabled"
  add_confidence 80
else
  info "Automatic diagnostic submission state unavailable or enabled"
  PRIV=$((PRIV-5))
  add_confidence 60
fi
info "Privacy posture is limited and does not inspect per-app permissions"

section "PATH SECURITY"
: > "$DIR/writable_path_dirs.log"

while IFS= read -r P; do
  case "$P" in
    /opt/homebrew/bin|/opt/homebrew/sbin|/usr/local/bin|/usr/local/sbin|/usr/bin|/bin|/sbin|/usr/sbin|"$HOME"/bin|"$HOME"/.local/bin) continue ;;
  esac
  if [ -d "$P" ] && [ -w "$P" ]; then
    printf "%s\n" "$P" >> "$DIR/writable_path_dirs.log"
  fi
done < <(scan_path_dirs)

WR=$(sort -u "$DIR/writable_path_dirs.log" 2>/dev/null | tee "$DIR/writable_path_dirs.log" | wc -l | tr -d ' ')
BIN=$(while IFS= read -r P; do
  case "$P" in
    /opt/homebrew/bin|/opt/homebrew/sbin|/usr/local/bin|/usr/local/sbin|/usr/bin|/bin|/sbin|/usr/sbin|"$HOME"/bin|"$HOME"/.local/bin) continue ;;
  esac
  [ -d "$P" ] && find "$P" -maxdepth 1 -type f -perm -111 2>/dev/null
done < <(scan_path_dirs) | wc -l | tr -d ' ')

info "Executable files in non-standard PATH dirs : $BIN"
if [ "$WR" -gt 0 ]; then
  warn "Writable non-trusted PATH directories detected : $WR"
  add_review_item "Writable non-trusted PATH directories detected: $WR"
  add_remediation "Review writable PATH directories listed in $DIR/writable_path_dirs.log"
  add_penalty 2
  add_confidence 80
else
  ok "No writable non-trusted PATH directories found"
  add_confidence 80
fi

section "NETWORK LISTENERS"
LISTEN_OUTPUT=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || true)
TCP=$(printf "%s\n" "$LISTEN_OUTPUT" | tail -n +2 | wc -l | tr -d ' ')
EXTERNAL_LISTENERS=$(printf "%s\n" "$LISTEN_OUTPUT" | grep -v "127.0.0.1\|localhost\|::1" | tail -n +2 | wc -l | tr -d ' ')
LOCAL_LISTENERS=$((TCP-EXTERNAL_LISTENERS))

info "Listeners          : $TCP"
info "External listeners : $EXTERNAL_LISTENERS"
info "Local listeners    : $LOCAL_LISTENERS"
info "Listener counts are contextual; developer machines often expose local services"

if [ "$EXTERNAL_LISTENERS" -gt 10 ]; then
  warn "High number of externally bound listeners"
  NET=$((NET-10))
  add_review_item "High number of externally bound listeners detected: $EXTERNAL_LISTENERS"
  add_remediation "Review listeners with: lsof -nP -iTCP -sTCP:LISTEN"
  add_penalty 2
  add_confidence 85
else
  add_confidence 85
fi

section "REMOTE MANAGEMENT SURFACE"
SCREEN_SHARING_STATE="unknown"
REMOTE_MANAGEMENT_STATE="unknown"

SS_CHECK=$(launchctl print-disabled system 2>/dev/null | grep -E 'com\.apple\.screensharing($| = )' || true)
RM_CHECK=$(launchctl print-disabled system 2>/dev/null | grep -E 'com\.apple\.ARDAgent($| = )' || true)

if printf "%s\n" "$SS_CHECK" | grep -qi '= true'; then
  SCREEN_SHARING_STATE="disabled"
elif printf "%s\n" "$SS_CHECK" | grep -qi '= false'; then
  SCREEN_SHARING_STATE="enabled"
fi

if printf "%s\n" "$RM_CHECK" | grep -qi '= true'; then
  REMOTE_MANAGEMENT_STATE="disabled"
elif printf "%s\n" "$RM_CHECK" | grep -qi '= false'; then
  REMOTE_MANAGEMENT_STATE="enabled"
fi

case "$SCREEN_SHARING_STATE" in
  disabled)
    ok "Screen Sharing disabled"
    add_confidence 80
    ;;
  enabled)
    warn "Screen Sharing enabled"
    ATTACK=$((ATTACK-10))
    add_review_item "Screen Sharing is enabled"
    add_remediation "Review Screen Sharing in System Settings > General > Sharing"
    add_penalty 2
    add_confidence 80
    ;;
  unknown)
    info "Screen Sharing status unavailable"
    add_visibility_gap "Screen Sharing status could not be confirmed"
    add_confidence 45
    ;;
esac

case "$REMOTE_MANAGEMENT_STATE" in
  disabled)
    ok "Remote Management disabled"
    add_confidence 80
    ;;
  enabled)
    warn "Remote Management enabled"
    ATTACK=$((ATTACK-10))
    add_review_item "Remote Management is enabled"
    add_remediation "Review Remote Management in System Settings > General > Sharing"
    add_penalty 3
    add_confidence 80
    ;;
  unknown)
    info "Remote Management status unavailable"
    add_visibility_gap "Remote Management status could not be confirmed"
    add_confidence 45
    ;;
esac

if launchctl list 2>/dev/null | grep -qi InternetSharing; then
  warn "Internet Sharing appears active"
  ATTACK=$((ATTACK-5))
  add_review_item "Internet Sharing appears active"
  add_remediation "Review Internet Sharing in System Settings > General > Sharing"
  add_penalty 1
  add_confidence 70
else
  info "Internet Sharing not detected"
  add_confidence 70
fi

section "ADMIN PROFILE"
ADMIN_LINE=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | awk -F': ' '/GroupMembership/ {print $2}' || true)
ADMIN_COUNT=$(printf "%s\n" "$ADMIN_LINE" | awk '{print NF}')
info "Admin group members      : ${ADMIN_LINE:-unavailable}"
info "Admin membership count   : ${ADMIN_COUNT:-0}"
add_confidence 85

section "BASELINE ENGINE"
TMP=$(mktemp)
DETAILS_TMP=$(mktemp)

{
  csrutil status 2>/dev/null || true
  spctl --status 2>/dev/null || true
  fdesetup status 2>/dev/null || true
  systemsetup -getremotelogin 2>/dev/null || true
  find "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons -type f 2>/dev/null | sort
} > "$TMP"

{
  echo "UA=$UA"
  echo "SA=$SA"
  echo "LD=$LD"
  echo "UTUN=$UTUN_COUNT"
  echo "EXT_LISTENERS=$EXTERNAL_LISTENERS"
  echo "UNSIGNED=$UNSIGNED"
  echo "NOT_SIGNED=$NOT_SIGNED"
  echo "LOCAL_MOD=$LOCAL_MOD"
  echo "NOT_NOTARIZED=$NOT_NOTARIZED"
  echo "BASE_INDEX_PRE=$((CORE*30 + NET*15 + PRIV*10 + PERSIST*15 + SIGNING*10 + ATTACK*20))"
} > "$DETAILS_TMP"

HASH=$(shasum -a 256 "$TMP" | awk '{print $1}')
printf "%s\n" "$HASH" > "$DIR/current.sha256"
cp "$DETAILS_TMP" "$DIR/current_baseline_details.txt"

if [ -f "$BASE" ]; then
  if cmp -s "$BASE" "$DIR/current.sha256"; then
    ok "Baseline unchanged"
    BASELINE_STATUS="unchanged"
    add_confidence 85
  else
    warn "Baseline drift detected"
    BASELINE_STATUS="drift-detected"
    add_review_item "Baseline drift detected"
    add_penalty 2
    add_confidence 85

    if [ -f "$BASE_DETAILS" ]; then
      while IFS='=' read -r key value; do
        old=$(grep "^${key}=" "$BASE_DETAILS" 2>/dev/null | head -n1 | cut -d'=' -f2-)
        new=$(grep "^${key}=" "$DETAILS_TMP" 2>/dev/null | head -n1 | cut -d'=' -f2-)
        [ -z "$old" ] && continue
        [ "$old" != "$new" ] && add_baseline_diff "${key}: ${old} -> ${new}"
      done < "$DETAILS_TMP"
    else
      add_baseline_diff "Detailed baseline comparison unavailable because no baseline details file was found"
    fi

    add_remediation "Review drift details below and accept only expected changes with: ./MacosSecurityAudit.sh --accept-baseline"

    if [ "$ACCEPT_BASELINE" -eq 1 ]; then
      cp "$DIR/current.sha256" "$BASE"
      cp "$DETAILS_TMP" "$BASE_DETAILS"
      info "Baseline updated because --accept-baseline was provided"
      BASELINE_STATUS="accepted-new-baseline"
    else
      info "Baseline not updated automatically; use --accept-baseline to accept changes"
    fi
  fi
else
  warn "No baseline file found"
  BASELINE_STATUS="missing"
  add_review_item "No baseline file found yet"
  add_penalty 1
  add_confidence 80
  add_baseline_diff "Baseline does not exist yet"
  add_remediation "Create the initial baseline after review with: ./MacosSecurityAudit.sh --accept-baseline"
  if [ "$ACCEPT_BASELINE" -eq 1 ]; then
    cp "$DIR/current.sha256" "$BASE"
    cp "$DETAILS_TMP" "$BASE_DETAILS"
    info "Baseline created because --accept-baseline was provided"
    BASELINE_STATUS="created"
  else
    info "Run again with --accept-baseline to create a baseline"
  fi
fi

BASELINE_STATUS_JSON=$(json_escape "$BASELINE_STATUS")
rm -f "$TMP" "$DETAILS_TMP"

for score_var in CORE NET PRIV PERSIST SIGNING ATTACK; do
  eval "v=\${$score_var}"
  [ "$v" -gt 100 ] && eval "$score_var=100"
  [ "$v" -lt 0 ] && eval "$score_var=0"
done

BASE_INDEX=$(((CORE*30 + NET*15 + PRIV*10 + PERSIST*15 + SIGNING*10 + ATTACK*20)/100))
[ "$BASE_INDEX" -gt 100 ] && BASE_INDEX=100
[ "$BASE_INDEX" -lt 0 ] && BASE_INDEX=0

POSTURE_INDEX=$((BASE_INDEX - OP_PENALTY))
[ "$POSTURE_INDEX" -gt 100 ] && POSTURE_INDEX=100
[ "$POSTURE_INDEX" -lt 0 ] && POSTURE_INDEX=0

if [ "$POSTURE_INDEX" -ge 95 ] && [ "$FAIL" -eq 0 ]; then
  POSTURE_LEVEL="STRONG POSTURE"
elif [ "$POSTURE_INDEX" -ge 80 ]; then
  POSTURE_LEVEL="REVIEW ADVISED"
elif [ "$POSTURE_INDEX" -ge 65 ]; then
  POSTURE_LEVEL="MODERATE REVIEW REQUIRED"
else
  POSTURE_LEVEL="ELEVATED REVIEW REQUIRED"
fi

if [ "$CONFIDENCE_COUNT" -gt 0 ]; then
  CONFIDENCE_SCORE=$((CONFIDENCE_TOTAL / CONFIDENCE_COUNT))
else
  CONFIDENCE_SCORE=0
fi
CONFIDENCE_LEVEL=$(confidence_label "$CONFIDENCE_SCORE")

REVIEW_COUNT=${#REVIEW_ITEMS[@]}
VISIBILITY_GAP_COUNT=${#VISIBILITY_GAPS[@]}
BASELINE_DIFF_COUNT=${#BASELINE_DIFFS[@]}

SEVERITY_LEVEL=$(severity_from_penalty "$OP_PENALTY")

REVIEW_HTML=$(render_html_list REVIEW_ITEMS "No review items recorded")
VISIBILITY_HTML=$(render_html_list VISIBILITY_GAPS "No visibility gaps recorded")
REMEDIATION_HTML=$(render_html_list REMEDIATIONS "No remediation commands recorded")
BASELINE_HTML=$(render_html_list BASELINE_DIFFS "No baseline differences recorded")

REVIEW_JSON_ITEMS=$(join_json_array REVIEW_ITEMS)
VISIBILITY_JSON_ITEMS=$(join_json_array VISIBILITY_GAPS)
REMEDIATION_JSON_ITEMS=$(join_json_array REMEDIATIONS)
BASELINE_JSON_ITEMS=$(join_json_array BASELINE_DIFFS)

if [ "$REVIEW_COUNT" -gt 0 ]; then
  ASSESSMENT_RATIONALE="Core protections appear generally strong, but confirmed review items reduced the final posture index."
elif [ "$VISIBILITY_GAP_COUNT" -gt 0 ]; then
  ASSESSMENT_RATIONALE="No confirmed review items were recorded, but visibility gaps reduced confidence in the overall assessment."
else
  ASSESSMENT_RATIONALE="No review items or visibility gaps were recorded; posture level derived from weighted control checks."
fi

POSTURE_LEVEL_JSON=$(json_escape "$POSTURE_LEVEL")
SEVERITY_LEVEL_JSON=$(json_escape "$SEVERITY_LEVEL")
CONFIDENCE_LEVEL_JSON=$(json_escape "$CONFIDENCE_LEVEL")
RATIONALE_JSON=$(json_escape "$ASSESSMENT_RATIONALE")
NOTARIZATION_ASSESSMENT_JSON=$(json_escape "$NOTARIZATION_ASSESSMENT")
SCREEN_SHARING_STATE_JSON=$(json_escape "$SCREEN_SHARING_STATE")
REMOTE_MANAGEMENT_STATE_JSON=$(json_escape "$REMOTE_MANAGEMENT_STATE")

section "POSTURE TELEMETRY"
info "Core security               : $CORE%"
info "Network posture             : $NET%"
info "Privacy posture             : $PRIV%"
info "Persistence posture         : $PERSIST%"
info "Application signing posture : $SIGNING%"
info "Attack surface              : $ATTACK%"
info "Base weighted index         : $BASE_INDEX / 100"
info "Operational penalty         : -$OP_PENALTY"
info "Final posture index         : $POSTURE_INDEX / 100"
info "Severity level              : $SEVERITY_LEVEL"
info "Confidence score            : $CONFIDENCE_SCORE / 100 ($CONFIDENCE_LEVEL)"
info "Notarization assessment     : $NOTARIZATION_ASSESSMENT ($NOTARIZATION_SCORE / 100)"

section "POSTURE SUMMARY"
bar "$CORE"    "CORE"
bar "$NET"     "NETWORK"
bar "$PRIV"    "PRIVACY"
bar "$PERSIST" "PERSISTENCE"
bar "$SIGNING" "APP SIGNING"
bar "$ATTACK"  "ATTACK SURFACE"

section "POSTURE ASSESSMENT"
if [ "$JSON_ONLY" -eq 0 ]; then
  echo "╔════════════════════════════════════╗"
  echo "║    NIGHTWATCH ASSESSMENT 3.2.2     ║"
  echo "╠════════════════════════════════════╣"
  printf "║ BASE        %-22s ║\n" "$BASE_INDEX / 100"
  printf "║ PENALTY     %-22s ║\n" "-$OP_PENALTY"
  printf "║ INDEX       %-22s ║\n" "$POSTURE_INDEX / 100"
  printf "║ POSTURE     %-22s ║\n" "$POSTURE_LEVEL"
  printf "║ SEVERITY    %-22s ║\n" "$SEVERITY_LEVEL"
  printf "║ CONFIDENCE  %-22s ║\n" "$CONFIDENCE_SCORE / 100"
  echo "╚════════════════════════════════════╝"
fi

section "REVIEW ITEMS"
if [ "$REVIEW_COUNT" -gt 0 ]; then
  for item in "${REVIEW_ITEMS[@]}"; do info "$item"; done
else
  info "No review items recorded"
fi

section "VISIBILITY GAPS"
if [ "$VISIBILITY_GAP_COUNT" -gt 0 ]; then
  for item in "${VISIBILITY_GAPS[@]}"; do info "$item"; done
else
  info "No visibility gaps recorded"
fi

section "BASELINE DIFF EXPLANATION"
if [ "$BASELINE_DIFF_COUNT" -gt 0 ]; then
  for item in "${BASELINE_DIFFS[@]}"; do info "$item"; done
else
  info "No baseline differences recorded"
fi

section "REMEDIATION COMMANDS"
if [ "${#REMEDIATIONS[@]}" -gt 0 ]; then
  for item in "${REMEDIATIONS[@]}"; do info "$item"; done
else
  info "No remediation commands recorded"
fi

section "METHODOLOGY"
info "Methodology: weighted heuristic index, not a security guarantee"
info "Severity reflects operational impact from confirmed review items"
info "Confidence reflects how directly controls could be verified"
info "Visibility gaps affect confidence, not severity"

section "HARDENING NOTES"
if [ "$NOTICE" -gt 0 ]; then
  info "Notice count : $NOTICE"
else
  info "No additional hardening notes"
fi

section "REPORT GENERATION"
cat > "$JSON" <<EOF_JSON
{
  "audit": $ID_JSON,
  "version": $VERSION_JSON,
  "machine": $HOST_JSON,
  "os": $OS_JSON,
  "build": $BUILD_JSON,
  "arch": $ARCH_JSON,
  "base_weighted_index": $BASE_INDEX,
  "operational_penalty": $OP_PENALTY,
  "posture_index": $POSTURE_INDEX,
  "posture_level": $POSTURE_LEVEL_JSON,
  "severity_level": $SEVERITY_LEVEL_JSON,
  "confidence_score": $CONFIDENCE_SCORE,
  "confidence_level": $CONFIDENCE_LEVEL_JSON,
  "passed": $PASS,
  "warnings": $WARN,
  "failed": $FAIL,
  "core_security": $CORE,
  "network_posture": $NET,
  "privacy_posture": $PRIV,
  "persistence_posture": $PERSIST,
  "application_signing_posture": $SIGNING,
  "attack_surface": $ATTACK,
  "utun_interfaces": $UTUN_COUNT,
  "listeners": $TCP,
  "external_listeners": $EXTERNAL_LISTENERS,
  "applications_scanned": $TOTAL,
  "unsigned_or_unverifiable_apps": $UNSIGNED,
  "not_signed_at_all": $NOT_SIGNED,
  "locally_modified_apps": $LOCAL_MOD,
  "obsolete_resource_envelope": $OBSOLETE_ENV,
  "architecture_only_verify_oddities": $ARCH_ONLY,
  "other_verify_failures": $OTHER_VERIFY,
  "notarized_count": $NOTARIZED,
  "developer_id_without_notarization_confirmation": $NOT_NOTARIZED,
  "notarization_unknown": $NOTARIZATION_UNKNOWN,
  "notarization_score": $NOTARIZATION_SCORE,
  "notarization_assessment": $NOTARIZATION_ASSESSMENT_JSON,
  "files_without_quarantine_xattr": $QX_MISSING,
  "files_quarantine_scope": $FILES,
  "baseline_status": $BASELINE_STATUS_JSON,
  "screen_sharing_state": $SCREEN_SHARING_STATE_JSON,
  "remote_management_state": $REMOTE_MANAGEMENT_STATE_JSON,
  "review_item_count": $REVIEW_COUNT,
  "review_items": [ $REVIEW_JSON_ITEMS ],
  "visibility_gap_count": $VISIBILITY_GAP_COUNT,
  "visibility_gaps": [ $VISIBILITY_JSON_ITEMS ],
  "baseline_diff_count": $BASELINE_DIFF_COUNT,
  "baseline_diffs": [ $BASELINE_JSON_ITEMS ],
  "remediation_count": ${#REMEDIATIONS[@]},
  "remediation_commands": [ $REMEDIATION_JSON_ITEMS ],
  "assessment_rationale": $RATIONALE_JSON,
  "methodology": "weighted heuristic index, not a security guarantee"
}
EOF_JSON

cat > "$HTML" <<EOF_HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nightwatch Audit Report 3.2.2</title>
<style>
body{background:#07110c;color:#d9fbe8;font-family:ui-monospace,Menlo,monospace;padding:32px;line-height:1.5}
.panel{border:1px solid #1dbd74;padding:24px;max-width:1100px;margin:auto;background:#0b1711}
h1,h2{margin:0 0 12px}
p{margin:6px 0;color:#c7ead8}
.muted{color:#8fb8a1}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:20px}
.metric{border:1px solid #173626;padding:14px;background:#0e1d16}
.bar{height:12px;background:#12241b;border:1px solid #214533;position:relative;margin-top:8px;margin-bottom:14px}
.fill{height:100%;background:#1dbd74}
.kpi{font-size:28px;color:#ffffff}
.label{color:#8fb8a1;font-size:13px;text-transform:uppercase;letter-spacing:.08em}
.summary,.rationale,.method{margin-top:24px;padding:16px;border:1px solid #173626;background:#0d1a14}
.review{margin-top:24px;padding:16px;border:1px solid #5b4a1a;background:#171307}
.visibility{margin-top:24px;padding:16px;border:1px solid #24445f;background:#0a1620}
.baseline{margin-top:24px;padding:16px;border:1px solid #4b2c64;background:#130b18}
.remediation{margin-top:24px;padding:16px;border:1px solid #2b5f2b;background:#0b180b}
.review ul,.visibility ul,.baseline ul,.remediation ul{margin:10px 0 0 18px;padding:0}
.review li{margin:6px 0;color:#f4ddb0}
.visibility li{margin:6px 0;color:#badcf4}
.baseline li{margin:6px 0;color:#dfc7f6}
.remediation li{margin:6px 0;color:#bfe8bf}
.scoreline{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-top:20px}
.scorebox{border:1px solid #173626;padding:14px;background:#0e1d16}
</style>
</head>
<body>
<div class="panel">
  <h1>macOS Nightwatch Audit Snapshot 3.2.2</h1>
  <p class="muted">Heuristic workstation posture analyzer for macOS. Not EDR, not forensic evidence, not compliance validation.</p>

  <div class="grid">
    <div class="metric"><div class="label">Machine</div><div>$HOST</div></div>
    <div class="metric"><div class="label">Audit ID</div><div>$ID</div></div>
    <div class="metric"><div class="label">Version</div><div>$VERSION</div></div>
    <div class="metric"><div class="label">macOS</div><div>$OS ($BUILD)</div></div>
    <div class="metric"><div class="label">Architecture</div><div>$ARCH</div></div>
    <div class="metric"><div class="label">Notarization assessment</div><div>$NOTARIZATION_ASSESSMENT ($NOTARIZATION_SCORE / 100)</div></div>
    <div class="metric"><div class="label">Base weighted index</div><div class="kpi">$BASE_INDEX / 100</div></div>
    <div class="metric"><div class="label">Operational penalty</div><div class="kpi">-$OP_PENALTY</div></div>
  </div>

  <div class="scoreline">
    <div class="scorebox"><div class="label">Final posture index</div><div class="kpi">$POSTURE_INDEX / 100</div></div>
    <div class="scorebox"><div class="label">Posture level</div><div class="kpi">$POSTURE_LEVEL</div></div>
    <div class="scorebox"><div class="label">Severity</div><div class="kpi">$SEVERITY_LEVEL</div></div>
    <div class="scorebox"><div class="label">Confidence</div><div class="kpi">$CONFIDENCE_SCORE / 100</div></div>
    <div class="scorebox"><div class="label">Review items</div><div class="kpi">$REVIEW_COUNT</div></div>
  </div>

  <div class="summary">
    <h2>Security posture summary</h2>
    <div class="label">Core security — $CORE%</div><div class="bar"><div class="fill" style="width:${CORE}%"></div></div>
    <div class="label">Network posture — $NET%</div><div class="bar"><div class="fill" style="width:${NET}%"></div></div>
    <div class="label">Privacy posture — $PRIV%</div><div class="bar"><div class="fill" style="width:${PRIV}%"></div></div>
    <div class="label">Persistence posture — $PERSIST%</div><div class="bar"><div class="fill" style="width:${PERSIST}%"></div></div>
    <div class="label">Application signing posture — $SIGNING%</div><div class="bar"><div class="fill" style="width:${SIGNING}%"></div></div>
    <div class="label">Attack surface — $ATTACK%</div><div class="bar"><div class="fill" style="width:${ATTACK}%"></div></div>
  </div>

  <div class="review">
    <h2>Review items</h2>
    $REVIEW_HTML
  </div>

  <div class="visibility">
    <h2>Visibility gaps</h2>
    $VISIBILITY_HTML
  </div>

  <div class="baseline">
    <h2>Baseline diff explanation</h2>
    $BASELINE_HTML
  </div>

  <div class="remediation">
    <h2>Remediation commands</h2>
    $REMEDIATION_HTML
  </div>

  <div class="rationale">
    <h2>Assessment rationale</h2>
    <p>$ASSESSMENT_RATIONALE</p>
  </div>

  <div class="grid">
    <div class="metric"><div class="label">Passed checks</div><div>$PASS</div></div>
    <div class="metric"><div class="label">Baseline</div><div>$BASELINE_STATUS</div></div>
    <div class="metric"><div class="label">Screen Sharing</div><div>$SCREEN_SHARING_STATE</div></div>
    <div class="metric"><div class="label">Remote Management</div><div>$REMOTE_MANAGEMENT_STATE</div></div>
    <div class="metric"><div class="label">Admin group members</div><div>$ADMIN_LINE</div></div>
    <div class="metric"><div class="label">Admin membership count</div><div>$ADMIN_COUNT</div></div>
  </div>

  <div class="method">
    <h2>Methodology</h2>
    <p>Weighted heuristic index, not a security guarantee.</p>
    <p>Severity reflects operational impact from confirmed review items. Confidence reflects how directly controls could be verified.</p>
  </div>
</div>
</body>
</html>
EOF_HTML

section "OUTPUT"
info "LOG  : $LOG"
info "JSON : $JSON"
info "HTML : $HTML"
info "Unsigned apps log          : $DIR/unsigned_apps.log"
info "Unsigned apps details      : $DIR/unsigned_apps_detailed.log"
info "Notarization log           : $DIR/notarization.log"
info "Writable PATH dirs log     : $DIR/writable_path_dirs.log"
info "No quarantine xattr log    : $DIR/no_quarantine_xattr.log"
info "Suspicious persistence log : $DIR/suspicious_persistence.log"
info "Baseline details snapshot  : $DIR/current_baseline_details.txt"

if [ "$JSON_ONLY" -eq 0 ]; then
  echo
  echo "════════════════════════════════════════"
  echo " NIGHTWATCH AUDIT COMPLETE"
  echo "════════════════════════════════════════"
fi
