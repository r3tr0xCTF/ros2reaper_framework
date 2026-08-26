#!/usr/bin/env bash
# lab/install_ros2.sh — Privileged half of setup: installs ROS2 Jazzy + deps.
# Run this once with sudo privileges, then run lab/build_workspace.sh (no sudo).
#
#   ! bash lab/install_ros2.sh      # run in Claude Code terminal (prompts sudo)
#   bash lab/build_workspace.sh     # no sudo needed

set -euo pipefail
RED='\033[91m'; GREEN='\033[92m'; CYAN='\033[96m'; NC='\033[0m'
info() { echo -e "${CYAN}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[+]${NC} $*"; }

UBUNTU_CODENAME=$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
case "$UBUNTU_CODENAME" in
  noble) ROS_DISTRO="jazzy"  ;;
  jammy) ROS_DISTRO="humble" ;;
  *)     echo "${RED}[X]${NC} Unsupported: $UBUNTU_CODENAME"; exit 1 ;;
esac
info "Ubuntu $UBUNTU_CODENAME → installing ROS2 $ROS_DISTRO"

if [ -f "/opt/ros/$ROS_DISTRO/setup.bash" ]; then
    ok "ROS2 $ROS_DISTRO already installed — skipping"
else
    sudo apt-get update -q
    sudo apt-get install -y software-properties-common curl gnupg lsb-release
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
        python3-colcon-common-extensions
    ok "ROS2 $ROS_DISTRO installed"
fi

if [ ! -f /etc/ros/rosdep/sources.list.d/20-default.list ]; then
    sudo rosdep init
fi

ok "Done. Now run:  bash lab/build_workspace.sh"
