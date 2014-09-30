sudo iw dev wlan0 interface add mon0 type monitor
sudo python ./core.py
sudo iw dev mon0 del
