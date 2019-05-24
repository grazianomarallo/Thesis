
#!/bin/bash
#Author Graziano Marallo
# Fuzzer Start
cwd=$(pwd)

usage ()
{
  echo 'Usage : ./start_fuzzing  [-option]*  '
  echo ' -n normal mode'
  echo ' -m ASAN' 
  echo ' -c Crash triage'
  echo ' -t Add Readme for execution'
  exit
}
if [ $# -eq 0 ]; then
    usage
fi

if [ $1 = "-p" ]; then
test="ptk";
elif [ $1 = "-g" ]; then
test="gtk"
elif [ $1 = "-b" ]; then 
test="ptk_gtk"
fi


echo "+++ Start Fuzzing +++"
echo
#XXX CREATE A NEW DIRECTORY WITH CURRENT DATE TO STORE NEW RESULTS XXX
echo "+++ Creating new folder for results +++"
day=$(date +"%d_%m_%Y")
time=$(date +"%H:%M:%S")
#mkdir ~/Documents/Thesis/fuzzer_result/$now &&
if [ ! -d ~/Krack/Thesis/fuzzer_result ]; then
    mkdir -p ~/Krack/Thesis/fuzzer_result;
echo "+++ Fuzzer Result folder created +++"
fi
if [ ! -d ~/Krack/Thesis/fuzzer_result/$day/$test ]; then
    mkdir -p ~/Krack//Thesis/fuzzer_result/$day/$test;
echo "+++ Fuzzer Result folder created +++"
fi

if [ $1 = "-p" ]; then
mkdir ~/Krack/Thesis/fuzzer_result/$day/$test/$time &&
if [ $? -eq 0 ]; then
     echo  "*** Done ***"
else
     echo   "XXX Error XXX"
fi
echo "+++ Creating input/output directory +++"
mkdir ~/Krack/Thesis/fuzzer_result/$day/$test/$time/input &&
mkdir ~/Krack/Thesis/fuzzer_result/$day/$test/$time/output &&
echo
echo  "*** Done ***"
echo
echo "+++ Creating input seeds +++"
echo
cp  ~/Krack/Thesis/data_message/data_message_krack.bin ~/Krack/Thesis/fuzzer_result/$day/$test/$time/input/
echo "+++ Copying source file and executable "
echo
cp ~/Krack/Thesis/iwd-gm/unit/test-eapol ~/Krack/Thesis/fuzzer_result/$day/$test/$time/
cp ~/Krack/Thesis/iwd-gm/unit/test-eapol.c ~/Krack/Thesis/fuzzer_result/$day/$test/$time/
echo "*** Done ***"
#XXX Handle gtk case

elif [ $1 = "-g" ]; then
mkdir ~/Krack/Thesis/fuzzer_result/$day/$test/$time &&
if [ $? -eq 0 ]; then
     echo  "*** Done ***"
else
     echo   "XXX Error XXX"
fi
echo "+++ Creating input/output directory +++"
mkdir ~/Krack/Thesis/fuzzer_result/$day/$test/$time/input &&
mkdir ~/Krack/Thesis/fuzzer_result/$day/$test/$time/output &&
echo
echo  "*** Done ***"
echo
echo "+++ Creating input seeds +++"
echo
cp  ~/Krack/Thesis/data_message/data_message_igtk_krack.bin ~/Krack/Thesis/fuzzer_result/$day/$test/$time/input/
echo "+++ Copying source file and executable "
echo
cp ~/Krack/Thesis/iwd-gm/unit/test-eapol ~/Krack/Thesis/fuzzer_result/$day/$test/$time/
cp ~/Thesis/iwd-gm/unit/test-eapol.c ~/Krack/Thesis/fuzzer_result/$day/$test/$time/
echo "*** Done ***"

#XXX Handle ptk_gtk case
elif [ $1 = "-b" ]; then
mkdir ~/Krack/Thesis/fuzzer_result/$day/$test/$time &&

if [ $? -eq 0 ]; then
     echo  "*** Done ***"
else
     echo   "XXX Error XXX"
fi
echo "+++ Creating input/output directory +++"
mkdir ~/Krack/Thesis/fuzzer_result/$day/$test/$time/input &&
mkdir ~/Krack/Thesis/fuzzer_result/$day/$test/$time/output &&
echo
echo  "*** Done ***"
echo
echo "+++ Creating input seeds +++"
echo
cp  ~/Krack/Thesis/data_message/data_message_910.bin ~/Krack/Thesis/fuzzer_result/$day/$test/$time/input/
echo "+++ Copying source file and executable "
echo
cp ~/Krack/Thesis/iwd-gm/unit/test-eapol ~/Krack/Thesis/fuzzer_result/$day/$test/$time/
cp ~/Krack/Thesis/iwd-gm/unit/test-eapol.c ~/Krack/Thesis/fuzzer_result/$day/$test/$time/
echo "*** Done ***"
fi


#XXX START FUZZER IN NORMALE MODE XXX
echo "+++ STARTING FUZZER +++"
echo


if [ $2 = "-t" ]; then
     echo $3 > ~/Krack/Thesis/fuzzer_result/$day/$test/$time/file_conf.txt
     ~/afl/afl-fuzz -i ~/Krack/Thesis/fuzzer_result/$day/$test/$time/input -o ~/Krack/Thesis/fuzzer_result/$day/$test/$time/output  ~/Krack/Thesis/iwd-gm/unit/test-eapol @@
fi


if [ $2 = "-n" ]; then
     ~/afl/afl-fuzz -i ~/Krack/Thesis/fuzzer_result/$day/$time/input -o ~/Krack/Thesis/fuzzer_result/$day/$time/output  ~/Krack/Thesis/iwd-gm/unit/test-eapol @@
fi
if [ $2 = "-a" ]; then
	~/afl/afl-fuzz -m none -i ~/Krack/Thesis/fuzzer_result/$day/$time/input -o ~/Krack/Thesis/fuzzer_result/$day/$time/output  ~/Krack/Thesis/iwd-gm/unit/test-eapol @@
fi
if [ $2 = "-c" ]; then
	~/afl/afl-fuzz -C  -i ~/Krack/Thesis/fuzzer_result/$day/$time/input -o ~/Krack/Thesis/fuzzer_result/$day/$time/output  ~/Krack/Thesis/iwd-gm/unit/test-eapol @@
fi

