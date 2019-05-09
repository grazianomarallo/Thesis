
#!/bin/bash
#Author Graziano Marallo
# Fuzzer Start
cwd=$(pwd)

echo "+++ Start Fuzzing +++"
echo
#XXX CREATE A NEW DIRECTORY WITH CURRENT DATE TO STORE NEW RESULTS XXX
echo "+++ Creating new folder for results +++"
day=$(date +"%d_%m_%Y")
time=$(date +"%H:%M:%S")
#mkdir ~/Documents/Thesis/fuzzer_result/$now &&
if [ ! -d ~/Thesis/fuzzer_result ]; then
    mkdir -p ~/Thesis/fuzzer_result;
echo "+++ Fuzzer Result folder created +++"
fi
if [ ! -d ~/Thesis/fuzzer_result/$day ]; then
    mkdir -p ~/Thesis/fuzzer_result/$day;
echo "+++ Fuzzer Result folder created +++"
fi


mkdir ~/Thesis/fuzzer_result/$day/$time &&
if [ $? -eq 0 ]; then
     echo  "*** Done ***"
else
     echo   "XXX Error XXX"
fi
echo

#XXX CREATE INPUT/OUTPUT FOLDER
#mkdir ~/Documents/Thesis/fuzzer_result/$now/input &&
#mkdir ~/Documents/Thesis/fuzzer_result/$now/output &&

echo "+++ Creating input/output directory +++"
mkdir ~/Thesis/fuzzer_result/$day/$time/input &&
mkdir ~/Thesis/fuzzer_result/$day/$time/output &&
echo
echo  "*** Done ***"
echo
#XXX STATICALLY CREATE INPUT FILE FOR FEEDING FUZZER
#    THIS SHOULD BE CHANGED IN ORDER TO FEED FUZZER WITH DIFFERENT INPUT
#    FOR THE MOMENT LET'S ASSUME IS ENOUGH TO FEED WITH KEY DATA
#   TODO FEED WITH NONCE/OTHER INTERESTING DATA
echo "+++ Creating input seeds +++"
echo
cp  ~/Thesis/data_message/data_message_35.bin ~/Thesis/fuzzer_result/$day/$time/input/
cp  ~/Thesis/data_message/data_message2931.bin ~/Thesis/fuzzer_result/$day/$time/input/


#XXX START FUZZER IN NORMALE MODE XXX
echo "+++ STARTING FUZZER +++"
echo


if [ $1 = "-n" ]; then
     ~/afl/afl-fuzz -i ~/Thesis/fuzzer_result/$day/$time/input -o ~/Thesis/fuzzer_result/$day/$time/output  ~/Thesis/iwd-gm/unit/test-eapol @@
else
     ~/afl/afl-fuzz -m none -i ~/Thesis/fuzzer_result/$day/$time/input -o ~/Thesis/fuzzer_result/$day/$time/output  ~/Thesis/iwd-gm/unit/test-eapol @@
fi

