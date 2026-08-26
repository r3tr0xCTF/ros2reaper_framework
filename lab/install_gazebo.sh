#!/usr/bin/env bash
# lab/install_gazebo.sh — Install Gazebo Harmonic + ROS2 Jazzy bridge packages.
# Run with: ! bash lab/install_gazebo.sh
set -euo pipefail

echo "[*] Installing Gazebo Harmonic + ros-jazzy-ros-gz bridge..."
sudo apt-get update -qq
sudo apt-get install -y \
    ros-jazzy-ros-gz \
    ros-jazzy-gz-ros2-control \
    ros-jazzy-robot-state-publisher \
    ros-jazzy-joint-state-publisher \
    ros-jazzy-xacro

echo ""
echo "[+] Done. Gazebo Harmonic is now installed."
echo "    Launch the sim lab with:"
echo "      bash lab/start_lab.sh gazebo"
