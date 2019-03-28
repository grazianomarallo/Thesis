#!/bin/bash 
#Author Graziano Marallo
# Fuzzer Start 
cwd=$(pwd)

echo "+++ Start Fuzzing +++"
echo
#XXX CREATE A NEW DIRECTORY WITH CURRENT DATE TO STORE NEW RESULTS XXX
echo "+++ Creating new folder for results +++"
now=$(date +"+%d_%m_%Y_%H:%M:%S")
mkdir ~/Documents/Thesis/fuzzer_result/$now &&
if [ $? -eq 0 ]; then
     echo  "*** Done ***" 
else
     echo   "XXX Error XXX"
fi
echo

#XXX CREATE INPUT/OUTPUT FOLDER

echo "+++ Creating input/output directory +++"
mkdir ~/Documents/Thesis/fuzzer_result/$now/input &&
mkdir ~/Documents/Thesis/fuzzer_result/$now/output &&
echo 
echo  "*** Done ***"
echo 

echo "+++ Creating input seeds +++"
echo
#cp  ~/Documents/Thesis/data_message/data_message_4 ~/Documents/Thesis/fuzzer_result/$now/input/
#cp  ~/Documents/Thesis/data_message/data_message_6 ~/Documents/Thesis/fuzzer_result/$now/input/
cp  ~/Documents/Thesis/data_message/data_message_3_6_del ~/Documents/Thesis/fuzzer_result/$now/input/


#XXX START FUZZER IN NORMALE MODE XXX
echo "+++ STARTING FUZZER +++"
echo


afl-fuzz -i ~/Documents/Thesis/fuzzer_result/$now/input -o ~/Documents/Thesis/fuzzer_result/$now/output  $cwd/iwd-gm/unit/test-eapol @@



