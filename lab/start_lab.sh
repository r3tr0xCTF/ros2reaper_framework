#!/usr/bin/env bash
# lab/start_lab.sh — Start the ROS2Reaper Phase 7 lab in two terminals.
#
# Terminal 1 (target / mock robot):
#   ./lab/start_lab.sh target [--model go2|g1|b2|h1] [--domain-id 0] [--verbose]
#
# Terminal 2 (attacker / ros2reaper):
#   ./lab/start_lab.sh attacker
#   # Then run any Phase 7 command, e.g.:
#   #   python3 ros2reaper.py unitree-recon --unitree-recon-mode full
#
# Or run both sides in tmux automatically:
#   ./lab/start_lab.sh tmux [--model go2]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
CYCLONE_CFG="$SCRIPT_DIR/cyclone_local.xml"

# Detect ROS2 distro
for D in jazzy humble foxy; do
    [ -f "/opt/ros/$D/setup.bash" ] && { ROS_DISTRO="$D"; break; }
done
: "${ROS_DISTRO:?ROS2 not found under /opt/ros — run lab/setup.sh first}"

# Unitree workspace
UNITREE_WS="$HOME/unitree_ros2_ws/install/setup.bash"
[ -f "$UNITREE_WS" ] || { echo "[X] Unitree workspace not built — run lab/setup.sh first"; exit 1; }

_source_env() {
    set +u
    source "/opt/ros/$ROS_DISTRO/setup.bash"
    source "$UNITREE_WS"
    export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
    export CYCLONEDDS_URI="file://$CYCLONE_CFG"
    export ROS_DOMAIN_ID="${ROS_DOMAIN_ID:-0}"
    set -u
    echo "[+] Environment ready (ROS2=$ROS_DISTRO, domain=$ROS_DOMAIN_ID, DDS=CycloneDDS)"
}

MODE="${1:-help}"
shift || true

case "$MODE" in
    target)
        echo "[*] Starting mock Unitree robot (target)..."
        _source_env
        echo "[*] Flushing ROS2 daemon (ensures clean graph discovery)..."
        ros2 daemon stop 2>/dev/null; sleep 1; ros2 daemon start 2>/dev/null; sleep 1
        exec python3 "$SCRIPT_DIR/mock_unitree.py" "$@"
        ;;

    attacker)
        echo "[*] Sourcing environment for attacker terminal..."
        _source_env
        echo ""
        echo "  Environment ready. Example Phase 7 commands:"
        echo ""
        echo "  # Full recon"
        echo "  python3 $REPO_DIR/ros2reaper.py unitree-recon --unitree-recon-mode full"
        echo ""
        echo "  # Sport API — damp (motor off)"
        echo "  python3 $REPO_DIR/ros2reaper.py unitree-api --unitree-api-mode damp"
        echo ""
        echo "  # Direct LowCmd motor injection"
        echo "  python3 $REPO_DIR/ros2reaper.py unitree-lowcmd --lowcmd-mode damp --robot-model go2"
        echo ""
        echo "  # Sport mode hijack — velocity lock 30s"
        echo "  python3 $REPO_DIR/ros2reaper.py unitree-sport --unitree-sport-mode velocity_lock \\"
        echo "    --sport-vx 0.5 --duration 30"
        echo ""
        exec bash --norc -i
        ;;

    tmux)
        command -v tmux >/dev/null 2>&1 || { echo "[X] tmux not installed: sudo apt install tmux"; exit 1; }
        SESSION="ros2reaper_lab"
        tmux has-session -t "$SESSION" 2>/dev/null && { tmux kill-session -t "$SESSION"; }

        MODEL="${1:-go2}"
        tmux new-session -d -s "$SESSION" -x 220 -y 50

        # Pane 0: target (mock robot)
        tmux send-keys -t "$SESSION:0" "bash $SCRIPT_DIR/start_lab.sh target --model $MODEL" Enter

        # Pane 1: attacker
        tmux split-window -h -t "$SESSION:0"
        sleep 1
        tmux send-keys -t "$SESSION:0.1" "bash $SCRIPT_DIR/start_lab.sh attacker" Enter

        tmux select-pane -t "$SESSION:0.0"
        tmux attach-session -t "$SESSION"
        ;;

    *)
        echo "Usage: $0 target [--model go2|g1|b2|h1] [--domain-id 0] [--verbose]"
        echo "       $0 attacker"
        echo "       $0 tmux [model]"
        echo ""
        echo "  target   — start the mock Unitree robot (the attack target)"
        echo "  attacker — source env and open attacker shell"
        echo "  tmux     — open both panes automatically in tmux"
        ;;
esac
