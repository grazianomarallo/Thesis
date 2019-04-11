#!/bin/bash 
#Author Graziano Marallo
# INITIALISE AFL  

echo 
echo "*** Cloning American Fuzzy Lop (AFL)  ***" 
cd ~/
git clone https://github.com/mirrorer/afl.git
echo ~/afl
echo "*** Done! ***" 
echo

echo "*** Building AFL ***"
cd 
make
echo "*** AFL built: OK! *** "
echo 
echo "*** Building IWD ***"
echo 

cd ~/Thesis/iwd-gm/
./bootstrap
CC=~/afl/afl-gcc ./configure
make
make test-suite.log

echo 
echo "*** Building Done ***"

