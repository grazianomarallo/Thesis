#!/bin/bash

#Initialiate the wifi adpater and set the config 

echo "James1308" | sudo -S  bash

#disable wifi 
echo "nmcli radio wifi off"
#unblock wifi 
echo "rfkill unblock wifi"
#insert and get dependeces of new kernel model
#to handle protocol x.80211
echo "sudo modprobe mac80211_hwsim radios=3"
#run hostapd in debug mode and K XXX
echo "hostapd hostapd.conf -dd -K"

