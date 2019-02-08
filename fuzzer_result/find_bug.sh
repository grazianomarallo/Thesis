#!/bin/bash 
#Author Graziano Marallo
#

echo "+++ Start finding error +++"
echo


if [ ! -d  $1/output/crashes/README.txt ]; then
    rm  $1/output/crashes/README.txt 
echo "+++ Readme file removed +++"
fi    
ls $1/output/crashes/ > tmp.txt


file="tmp.txt"
while IFS= read -r line
do
        echo "XXXXXXXXXXXXXXXXXXXXXXXSTARTXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        echo
        echo "Analysing file:  $line"
        echo
        ../iwd-gm/unit/test-eapol $1/output/crashes/$line 
        echo 
        echo "XXXXXXXXXXXXXXXXXXXXXXXXENDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        echo
done <"$file"

rm tmp.txt

echo "+++ DONE+++ "
echo
