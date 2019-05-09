#!/bin/bash  
#Author Graziano Marallo
# Coverage Start 
cwd=$(pwd)

usage ()
{
  echo 'Usage : ./start_cov.sh -d <result_dir> | -o to overwrite old results  '
  echo 
  exit
}


if  [[ $# -eq 0 ]]; then
    usage
fi

if  [[ $1 = "-d" ]]; then
    echo "+++ Starting coverage analysis +++"
    echo
    cd ../iwd-gm-cov/unit
	~/afl-cov/afl-cov -d ~/Thesis/fuzzer_result/$2/output --coverage-cmd "./test-eapol AFL_FILE" --code-dir .
fi


if  [[ $1 = "-d" && $3 = "-o" ]]; then
    echo "+++ Starting coverage analysis +++"
    echo
    cd ../iwd-gm-cov/unit
	~/afl-cov/afl-cov -d ~/Thesis/fuzzer_result/$2/output --coverage-cmd "./test-eapol AFL_FILE" --code-dir . --overwrite
fi





