#!/usr/bin/env bash
# lab/build_workspace.sh — No-sudo: clone + build Unitree ROS2 workspace.
# Run after install_ros2.sh completes.

set -euo pipefail
RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; YELLOW='\033[93m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

for D in jazzy humble foxy; do
    [ -f "/opt/ros/$D/setup.bash" ] && { ROS_DISTRO="$D"; break; }
done
: "${ROS_DISTRO:?ROS2 not found — run lab/install_ros2.sh first}"
info "Using ROS2 $ROS_DISTRO"

set +u
source "/opt/ros/$ROS_DISTRO/setup.bash"
set -u

rosdep update --rosdistro "$ROS_DISTRO" -q
ok "rosdep updated"

WS="$HOME/unitree_ros2_ws"
SRC="$WS/src/unitree_ros2"

if [ -d "$SRC" ]; then
    info "Pulling latest unitree_ros2..."
    git -C "$SRC" pull --ff-only 2>/dev/null || warn "git pull skipped (local changes)"
else
    info "Cloning unitree_ros2..."
    mkdir -p "$WS/src"
    git clone --depth 1 https://github.com/unitreerobotics/unitree_ros2.git "$SRC"
fi

info "Running rosdep install..."
cd "$WS"
rosdep install --from-paths src --ignore-src -r -y -q 2>/dev/null || true

info "Building with colcon..."
colcon build \
    --symlink-install \
    --cmake-args -DCMAKE_BUILD_TYPE=Release \
    --parallel-workers "$(nproc)" \
    2>&1 | grep -E '(Starting|Finished|Failed|Error|error:|warning:|packages)' || true

ok "Build complete: $WS/install"

# ── Write env file (source this in any terminal to use the lab) ───────────────
ENV_FILE="$SCRIPT_DIR/lab_env.sh"
cat > "$ENV_FILE" <<ENVEOF
# Source this to set up the ROS2Reaper Phase 7 lab environment.
#   source lab/lab_env.sh
source /opt/ros/$ROS_DISTRO/setup.bash
source $WS/install/setup.bash
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export CYCLONEDDS_URI=file://$SCRIPT_DIR/cyclone_local.xml
export ROS_DOMAIN_ID=\${ROS_DOMAIN_ID:-0}
echo "[+] Lab env: ROS2=$ROS_DISTRO  domain=\$ROS_DOMAIN_ID  DDS=CycloneDDS (loopback)"
ENVEOF
ok "Wrote $ENV_FILE"

# ── Update ~/.bashrc ──────────────────────────────────────────────────────────
MARKER="# ROS2Reaper lab"
if ! grep -qF "$MARKER" ~/.bashrc; then
    {
        echo ""
        echo "$MARKER"
        cat "$ENV_FILE"
    } >> ~/.bashrc
    ok "Appended lab env to ~/.bashrc"
fi

echo ""
ok "============================================================"
ok " Lab ready!"
ok "============================================================"
echo ""
echo "  Terminal 1 — start mock robot:"
echo "    source lab/lab_env.sh"
echo "    python3 lab/mock_unitree.py --model go2 --verbose"
echo ""
echo "  Terminal 2 — run attacks:"
echo "    source lab/lab_env.sh"
echo "    python3 ros2reaper.py unitree-recon --unitree-recon-mode full"
echo ""
echo "  Or in one step with tmux:"
echo "    ./lab/start_lab.sh tmux go2"
echo ""
