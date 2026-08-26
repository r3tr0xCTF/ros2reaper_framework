# Source this to set up the ROS2Reaper Phase 7 lab environment.
#   source lab/lab_env.sh
source /opt/ros/jazzy/setup.bash
source /home/retro/unitree_ros2_ws/install/setup.bash
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export CYCLONEDDS_URI=file:///home/retro/ros2reaper_framework/lab/cyclone_local.xml
export ROS_DOMAIN_ID=${ROS_DOMAIN_ID:-0}
echo "[+] Lab env: ROS2=jazzy  domain=$ROS_DOMAIN_ID  DDS=CycloneDDS (loopback)"
