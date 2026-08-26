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
        ros2 daemon stop 2>/dev/null || true; sleep 1
        ros2 daemon start 2>/dev/null || true; sleep 1
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

    gazebo)
        # ── rviz2 visualization lab (replaces Gazebo — Ogre2 broken on this system) ──
        echo "[*] Starting rviz2 visualization lab..."
        _source_env

        echo "[*] Stopping any previous lab processes..."
        pkill -f "unitree_gz_translator" 2>/dev/null || true
        pkill -f "robot_state_publisher" 2>/dev/null || true
        sleep 1

        echo "[*] Flushing ROS2 daemon..."
        ros2 daemon stop 2>/dev/null || true; sleep 1
        ros2 daemon start 2>/dev/null || true; sleep 1

        URDF="$SCRIPT_DIR/go2.urdf"
        RVIZ_CFG="$SCRIPT_DIR/go2.rviz"
        URDF_CONTENT="$(cat "$URDF")"

        echo "[*] Starting robot_state_publisher..."
        ros2 run robot_state_publisher robot_state_publisher \
            --ros-args -p robot_description:="$URDF_CONTENT" &
        RSP_PID=$!
        sleep 1

        echo "[*] Starting Unitree translator (homing controller + attack listener + JointState)..."
        python3 "$SCRIPT_DIR/unitree_gz_translator.py" &
        TRANS_PID=$!

        echo ""
        printf "\033[92m[+] robot_state_publisher and translator running\033[0m\n"
        echo "    PIDs: rsp=$RSP_PID  translator=$TRANS_PID"
        echo ""
        printf "\033[93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
        printf "\033[93m  OPEN A DESKTOP TERMINAL and run rviz2:\033[0m\n"
        printf "\033[93m\033[0m\n"
        printf "\033[93m    source /opt/ros/jazzy/setup.bash\033[0m\n"
        printf "\033[93m    DISPLAY=:1 QT_QPA_PLATFORM=xcb rviz2 -d $RVIZ_CFG\033[0m\n"
        printf "\033[93m\033[0m\n"
        printf "\033[93m  The Go2 robot model appears and homes to standing in ~3s.\033[0m\n"
        printf "\033[93m  Attacks visually move the joints in real time.\033[0m\n"
        printf "\033[93m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n"
        echo ""
        echo "    Attack from another terminal (source lab_env.sh first):"
        echo "      python3 $REPO_DIR/ros2reaper.py unitree-api --unitree-api-mode damp --skip-auth --no-banner"
        echo "      python3 $REPO_DIR/ros2reaper.py unitree-sport --unitree-sport-mode velocity_lock --sport-vx 0.5 --duration 10 --skip-auth --no-banner"
        echo "      python3 $REPO_DIR/ros2reaper.py unitree-lowcmd --lowcmd-mode damp --robot-model go2 --skip-auth --no-banner"
        echo ""
        echo "    Ctrl+C to stop."
        echo ""

        trap "echo '[*] Stopping...'; kill $RSP_PID $TRANS_PID 2>/dev/null" INT TERM
        wait $RSP_PID
        kill $TRANS_PID 2>/dev/null
        echo "[+] Visualization processes stopped."
        ;;

    *)
        echo "Usage: $0 target [--model go2|g1|b2|h1] [--domain-id 0] [--verbose]"
        echo "       $0 attacker"
        echo "       $0 tmux [model]"
        echo "       $0 gazebo"
        echo ""
        echo "  target   — start the mock Unitree robot (the DDS-only attack target)"
        echo "  attacker — source env and open attacker shell"
        echo "  tmux     — open both panes automatically in tmux"
        echo "  gazebo   — rviz2 visualization (robot model responds to attacks in real time)"
        ;;
esac
