#!/bin/bash 
#Author Graziano Marallo
# INITIALISE AFL  

echo 
echo "*** Cloning American Fuzzy Lop (AFL)  ***" 
cd ~/
git clone https://github.com/mirrorer/afl.git
echo 
echo "*** Done! ***" 
echo

echo "*** Building AFL ***"
cd ~/afl
make
echo "*** AFL built: OK! *** "
echo 
echo "*** Building IWD ***"
echo 

#!!! NOTE !!!
#if debian system run also this
#sudo apt install libtool libreadline-dev libdbus-glib-1-dev

echo "***  AFL Coverage  ***"
cd ~/
git clone https://github.com/mrash/afl-cov.git
cd ~/afl-cov
sudo apt-get install lcov
echo
echo "*** Done! ***"
echo



cd ~/Thesis/iwd-gm/
./bootstrap
CC=~/afl/afl-gcc ./configure
make
make test-suite.log

echo 
echo "*** Building Done ***"

