#!/bin/bash 
#Author Graziano Marallo
# INITIALISE AFL  

echo 
echo "*** Cloning American Fuzzy Lop (AFL)  ***" 
git clone https://github.com/mirrorer/afl.git
echo
echo "*** Done! ***" 
echo

echo "Removing Report"
rm -r Report

echo "*** Building AFL ***"

cd afl/
make

echo "*** AFL built: OK! *** "
cd ..
echo 

echo "*** Building IWD ***"
echo 

cd iwd-gm/
./bootstrap
CC=../afl/afl-gcc ./configure
make
make test-suite.log

echo 
echo "*** Building Done ***"

