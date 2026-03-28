#!/usr/bin/env bash
# =============================================================================
# RedAmon CLI - Simplified installation, update, and lifecycle management
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/.redamon"
VERSION_FILE="$SCRIPT_DIR/VERSION"

# Service lists
CORE_SERVICES="postgres neo4j recon-orchestrator kali-sandbox agent webapp"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

print_banner() {
    echo -e "${RED}${BOLD}"
    echo "  ____          _    _                         "
    echo " |  _ \\ ___  __| |  / \\   _ __ ___   ___  _ __"
    echo " | |_) / _ \\/ _\` | / _ \\ | '_ \` _ \\ / _ \\| '_ \\ "
    echo " |  _ <  __/ (_| |/ ___ \\| | | | | | (_) | | | |"
    echo " |_| \\_\\___|\\__,_/_/   \\_\\_| |_| |_|\\___/|_| |_|"
    echo -e "${NC}"
}

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        cat "$VERSION_FILE" | tr -d '[:space:]'
    else
        echo "unknown"
    fi
}

read_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        return 1
    fi
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
}

write_config() {
    local gvm_mode="$1"
    local version
    version="$(get_version)"
    cat > "$CONFIG_FILE" <<EOF
GVM_MODE=$gvm_mode
INSTALLED_VERSION=$version
EOF
}

check_prerequisites() {
    local missing=0

    if ! command -v docker &>/dev/null; then
        error "Docker is not installed. See: https://docs.docker.com/get-docker/"
        missing=1
    fi

    if ! docker compose version &>/dev/null; then
        error "Docker Compose v2 is not installed. See: https://docs.docker.com/compose/install/"
        missing=1
    fi

    if ! command -v git &>/dev/null; then
        error "Git is not installed."
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

export_version() {
    export REDAMON_VERSION
    REDAMON_VERSION="$(get_version)"
}

remove_redamon_images() {
    # Remove locally-built redamon images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep '^redamon-' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove GVM / Greenbone images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep 'registry.community.greenbone.net' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove ProjectDiscovery + recon tool images (pulled at runtime by entrypoint)
    local runtime_images=(
        "projectdiscovery/naabu"
        "projectdiscovery/httpx"
        "projectdiscovery/katana"
        "projectdiscovery/nuclei"
        "projectdiscovery/subfinder"
        "projectdiscovery/dnsx"
        "sxcurity/gau"
        "caffix/amass"
        "frost19k/puredns"
        "jauderho/hakrawler"
        "trufflesecurity/trufflehog"
    )
    for img in "${runtime_images[@]}"; do
        docker rmi "$img" 2>/dev/null || true
    done
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_install() {
    local gvm_mode="false"
    if [[ "${1:-}" == "--gvm" ]]; then
        gvm_mode="true"
    fi

    print_banner
    check_prerequisites

    local version
    version="$(get_version)"
    info "Installing RedAmon v${version}..."
    if [[ "$gvm_mode" == "true" ]]; then
        info "Mode: Full stack (with GVM/OpenVAS)"
    else
        info "Mode: Core services (without GVM/OpenVAS)"
    fi
    echo ""

    # Write config
    write_config "$gvm_mode"

    # Export version for docker build arg
    export_version

    # Build all images (tools + core services)
    info "Building all images (this may take a while on first run)..."
    docker compose --profile tools build

    # Start services
    info "Starting services..."
    if [[ "$gvm_mode" == "true" ]]; then
        docker compose up -d
    else
        # shellcheck disable=SC2086
        docker compose up -d $CORE_SERVICES
    fi

    echo ""
    success "RedAmon v${version} installed and running!"
    echo ""
    echo -e "  ${CYAN}Webapp:${NC}  http://localhost:3000"
    echo -e "  ${CYAN}Status:${NC}  ./redamon.sh status"
    echo ""
    if [[ "$gvm_mode" == "true" ]]; then
        warn "GVM/OpenVAS feed sync takes ~30 minutes on first run."
        echo -e "  ${CYAN}GVM credentials:${NC} admin / admin"
    fi
}

cmd_update() {
    if ! read_config; then
        error "No installation found. Run './redamon.sh install' first."
        exit 1
    fi

    print_banner
    check_prerequisites

    local old_version="${INSTALLED_VERSION:-unknown}"
    info "Current version: v${old_version}"
    info "Checking for updates..."
    echo ""

    # Save current HEAD
    local old_head new_head
    old_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

    # Pull latest (try upstream tracking branch first, then origin/master)
    if ! git -C "$SCRIPT_DIR" pull --ff-only 2>/dev/null; then
        if ! git -C "$SCRIPT_DIR" pull --ff-only origin master 2>/dev/null; then
            error "Could not pull updates. You may have local changes."
            echo ""
            echo "  Try one of:"
            echo "    git stash && ./redamon.sh update && git stash pop"
            echo "    git commit -am 'local changes' && ./redamon.sh update"
            exit 1
        fi
    fi

    new_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

    if [[ "$old_head" == "$new_head" ]]; then
        success "Already up to date (v$(get_version))."
        return
    fi

    local new_version
    new_version="$(get_version)"
    info "Updating v${old_version} -> v${new_version}"
    echo ""

    # Detect what changed
    local changed_files
    changed_files="$(git -C "$SCRIPT_DIR" diff --name-only "$old_head" "$new_head")"

    # Map changed paths to services
    local rebuild_core=()
    local rebuild_tools=()
    local rebuild_all=false

    if echo "$changed_files" | grep -q "^docker-compose\.yml$"; then
        rebuild_all=true
    fi

    # Track services that need restart only (volume-mounted source code changes)
    local restart_only=()

    if [[ "$rebuild_all" == "true" ]]; then
        info "docker-compose.yml changed -- rebuilding all images"
        rebuild_core=(recon-orchestrator kali-sandbox agent webapp)
        rebuild_tools=(recon vuln-scanner github-secret-hunter trufflehog-scanner)
    else
        # webapp: always needs rebuild (no volume mount in production)
        if echo "$changed_files" | grep -q "^webapp/"; then
            rebuild_core+=(webapp)
        fi

        # recon-orchestrator: rebuild only if Dockerfile/requirements changed, else restart
        if echo "$changed_files" | grep -q "^recon_orchestrator/\(Dockerfile\|requirements\)"; then
            rebuild_core+=(recon-orchestrator)
        elif echo "$changed_files" | grep -q "^recon_orchestrator/"; then
            restart_only+=(recon-orchestrator)
        fi

        # kali-sandbox: rebuild only if Dockerfile/entrypoint changed, else restart
        if echo "$changed_files" | grep -q "^mcp/kali-sandbox/\(Dockerfile\|entrypoint\)"; then
            rebuild_core+=(kali-sandbox)
        elif echo "$changed_files" | grep -q "^mcp/"; then
            restart_only+=(kali-sandbox)
        fi

        # agent: rebuild only if Dockerfile/requirements changed, else restart
        if echo "$changed_files" | grep -q "^agentic/\(Dockerfile\|requirements\)"; then
            rebuild_core+=(agent)
        elif echo "$changed_files" | grep -q "^agentic/"; then
            restart_only+=(agent)
        fi

        # Tool-profile images (build-only, not running containers)
        if echo "$changed_files" | grep -q "^recon/"; then
            rebuild_tools+=(recon)
        fi
        if echo "$changed_files" | grep -q "^gvm_scan/"; then
            rebuild_tools+=(vuln-scanner)
        fi
        if echo "$changed_files" | grep -q "^github_secret_hunt/"; then
            rebuild_tools+=(github-secret-hunter)
        fi
        if echo "$changed_files" | grep -q "^trufflehog_scan/"; then
            rebuild_tools+=(trufflehog-scanner)
        fi
    fi

    # Export version for build arg
    export_version

    # Rebuild tool-profile images
    if [[ ${#rebuild_tools[@]} -gt 0 ]]; then
        info "Rebuilding tool images: ${rebuild_tools[*]}"
        docker compose --profile tools build "${rebuild_tools[@]}"
    fi

    # Rebuild core service images
    if [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Rebuilding service images: ${rebuild_core[*]}"
        docker compose build "${rebuild_core[@]}"
    fi

    # Clean up dangling images left by rebuilds
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        docker image prune -f >/dev/null 2>&1 || true
    fi

    # Restart rebuilt core services (tool images are build-only, not running)
    if [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Restarting rebuilt services..."
        for svc in "${rebuild_core[@]}"; do
            docker compose up -d --no-deps "$svc"
        done
    fi

    # Restart services with volume-mounted code changes (no rebuild needed)
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        info "Restarting services for code changes: ${restart_only[*]}"
        docker compose restart "${restart_only[@]}"
    fi

    # Update config
    write_config "$GVM_MODE"

    echo ""
    success "Updated to v${new_version}!"
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        local rebuilt_list="${rebuild_core[*]:+${rebuild_core[*]} }${rebuild_tools[*]}"
        echo -e "  ${CYAN}Rebuilt:${NC}  ${rebuilt_list}"
    fi
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        echo -e "  ${CYAN}Restarted:${NC} ${restart_only[*]}"
    fi
    if [[ ${#rebuild_core[@]} -eq 0 && ${#rebuild_tools[@]} -eq 0 && ${#restart_only[@]} -eq 0 ]]; then
        info "No container images or source code needed updating."
    fi
    echo -e "  ${CYAN}Webapp:${NC}  http://localhost:3000"
}

cmd_up() {
    if ! read_config; then
        error "No installation found. Run './redamon.sh install' first."
        exit 1
    fi

    info "Starting RedAmon (GVM: ${GVM_MODE})..."

    if [[ "$GVM_MODE" == "true" ]]; then
        docker compose up -d
    else
        # shellcheck disable=SC2086
        docker compose up -d $CORE_SERVICES
    fi

    success "RedAmon is running at http://localhost:3000"
}

cmd_down() {
    info "Stopping RedAmon..."
    docker compose down
    success "All services stopped. Volumes and images preserved."
}

cmd_clean() {
    warn "This will remove all RedAmon containers and images."
    warn "Your data (databases, reports, scan results) will be preserved in Docker volumes."
    echo ""
    read -rp "Continue? [y/N] " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers..."
    docker compose --profile tools down

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    success "All RedAmon containers and images removed. Volumes preserved."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

cmd_purge() {
    echo ""
    warn "This will PERMANENTLY DELETE:"
    warn "  - All RedAmon containers and images"
    warn "  - ALL DATA: PostgreSQL, Neo4j, GVM feeds, reports, scan results"
    echo ""
    echo -e "${RED}${BOLD}This action cannot be undone.${NC}"
    echo ""
    read -rp "Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers and removing volumes..."
    docker compose --profile tools down --volumes --remove-orphans

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    rm -f "$CONFIG_FILE"
    success "Full cleanup complete. All RedAmon data and images have been removed."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

cmd_status() {
    local version
    version="$(get_version)"

    print_banner
    echo -e "  ${CYAN}Version:${NC}  v${version}"

    if read_config; then
        echo -e "  ${CYAN}GVM:${NC}      ${GVM_MODE}"
        echo -e "  ${CYAN}Installed:${NC} v${INSTALLED_VERSION:-unknown}"
    else
        echo -e "  ${YELLOW}Not installed via redamon.sh${NC}"
    fi
    echo ""

    docker compose ps
}

cmd_help() {
    print_banner
    echo -e "${BOLD}Usage:${NC} ./redamon.sh <command> [options]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}install${NC}          Build and start RedAmon (without GVM)"
    echo -e "  ${GREEN}install --gvm${NC}    Build and start RedAmon (with GVM/OpenVAS)"
    echo -e "  ${GREEN}update${NC}           Pull latest version and smart-rebuild changed services"
    echo -e "  ${GREEN}up${NC}               Start services"
    echo -e "  ${GREEN}down${NC}             Stop services (preserves data)"
    echo -e "  ${GREEN}clean${NC}            Remove containers and images (keeps data)"
    echo -e "  ${GREEN}purge${NC}            Remove everything including all data"
    echo -e "  ${GREEN}status${NC}           Show running services, version, and GVM mode"
    echo -e "  ${GREEN}help${NC}             Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./redamon.sh install          # First-time setup (no GVM)"
    echo "  ./redamon.sh install --gvm    # First-time setup (full stack)"
    echo "  ./redamon.sh update           # Update to latest version"
    echo "  ./redamon.sh up               # Start after reboot"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

cd "$SCRIPT_DIR"

case "${1:-help}" in
    install) cmd_install "${2:-}" ;;
    update)  cmd_update ;;
    up)      cmd_up ;;
    down)    cmd_down ;;
    clean)   cmd_clean ;;
    purge)   cmd_purge ;;
    status)  cmd_status ;;
    help|--help|-h) cmd_help ;;
    *)
        error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
