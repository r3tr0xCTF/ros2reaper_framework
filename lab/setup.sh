#!/usr/bin/env bash
# lab/setup.sh — ROS2Reaper Phase 7 Lab Setup
# Installs ROS2 Jazzy, CycloneDDS, and builds the Unitree ROS2 message workspace.
# Tested on Ubuntu 24.04 / Pop!_OS 24.04.
#
# Usage:
#   chmod +x lab/setup.sh
#   ./lab/setup.sh
#
# After completion:
#   source ~/unitree_ros2_ws/install/setup.bash
#   python3 lab/start_lab.sh   # (or run mock_unitree.py directly)

set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'; CYAN='\033[96m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[X]${NC} $*"; exit 1; }

# ── Detect Ubuntu codename ────────────────────────────────────────────────────
UBUNTU_CODENAME=$(. /etc/os-release 2>/dev/null && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}" || lsb_release -cs)
case "$UBUNTU_CODENAME" in
  noble)   ROS_DISTRO="jazzy"  ;;
  jammy)   ROS_DISTRO="humble" ;;
  focal)   ROS_DISTRO="foxy"   ;;
  *)       die "Unsupported Ubuntu codename: $UBUNTU_CODENAME (need noble/jammy/focal)" ;;
esac
info "Ubuntu: $UBUNTU_CODENAME → ROS2 distro: $ROS_DISTRO"

# ── ROS2 installation ─────────────────────────────────────────────────────────
if [ -f "/opt/ros/$ROS_DISTRO/setup.bash" ]; then
    ok "ROS2 $ROS_DISTRO already installed at /opt/ros/$ROS_DISTRO"
else
    info "Installing ROS2 $ROS_DISTRO..."
    sudo apt-get update -q
    sudo apt-get install -y software-properties-common curl
    sudo add-apt-repository -y universe

    sudo curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key \
        -o /usr/share/keyrings/ros-archive-keyring.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] \
http://packages.ros.org/ros2/ubuntu $UBUNTU_CODENAME main" \
        | sudo tee /etc/apt/sources.list.d/ros2.list > /dev/null

    sudo apt-get update -q
    sudo apt-get install -y \
        ros-${ROS_DISTRO}-desktop \
        ros-${ROS_DISTRO}-rmw-cyclonedds-cpp \
        python3-rosdep \
        python3-colcon-common-extensions \
        python3-vcstool
    ok "ROS2 $ROS_DISTRO installed"
fi

# ── rosdep ────────────────────────────────────────────────────────────────────
if [ ! -f /etc/ros/rosdep/sources.list.d/20-default.list ]; then
    info "Initialising rosdep..."
    sudo rosdep init
fi
rosdep update --rosdistro "$ROS_DISTRO" -q
ok "rosdep ready"

# ── Unitree ROS2 workspace ────────────────────────────────────────────────────
WS="$HOME/unitree_ros2_ws"
UNITREE_SRC="$WS/src/unitree_ros2"

if [ -d "$UNITREE_SRC" ]; then
    info "Unitree workspace already present at $WS — pulling latest..."
    git -C "$UNITREE_SRC" pull --ff-only || warn "git pull failed, continuing with existing checkout"
else
    info "Cloning unitree_ros2..."
    mkdir -p "$WS/src"
    git clone --depth 1 https://github.com/unitreerobotics/unitree_ros2.git "$UNITREE_SRC"
fi

info "Building Unitree workspace (colcon)..."
source "/opt/ros/$ROS_DISTRO/setup.bash"

cd "$WS"
rosdep install --from-paths src --ignore-src -r -y -q 2>/dev/null || true

colcon build \
    --symlink-install \
    --cmake-args -DCMAKE_BUILD_TYPE=Release \
    --event-handlers console_cohesion+ \
    2>&1 | tail -20

ok "Unitree workspace built: $WS/install"

# ── Shell config ──────────────────────────────────────────────────────────────
SETUP_LINE="source $WS/install/setup.bash"
SHELL_RC="$HOME/.bashrc"
if ! grep -qF "$SETUP_LINE" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# ROS2Reaper lab — Unitree workspace" >> "$SHELL_RC"
    echo "source /opt/ros/$ROS_DISTRO/setup.bash" >> "$SHELL_RC"
    echo "$SETUP_LINE" >> "$SHELL_RC"
    echo "export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp" >> "$SHELL_RC"
    ok "Added workspace source to $SHELL_RC"
fi

# ── CycloneDDS config symlink ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/cyclone_local.xml" ]; then
    CDDS_LINE="export CYCLONEDDS_URI=file://$SCRIPT_DIR/cyclone_local.xml"
    if ! grep -qF "CYCLONEDDS_URI" "$SHELL_RC"; then
        echo "$CDDS_LINE" >> "$SHELL_RC"
        ok "Added CYCLONEDDS_URI to $SHELL_RC"
    fi
fi

echo ""
ok "============================================================"
ok " Lab setup complete!"
ok "============================================================"
echo ""
echo "  Next steps:"
echo "    1. Reload your shell:  source ~/.bashrc"
echo "    2. Start the mock robot (in one terminal):"
echo "       python3 $SCRIPT_DIR/mock_unitree.py --model go2"
echo "    3. Run Phase 7 attacks (in another terminal):"
echo "       python3 ros2reaper.py unitree-recon --unitree-recon-mode full"
echo ""
