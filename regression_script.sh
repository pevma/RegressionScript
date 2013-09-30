#!/bin/bash
# the script takes one directory as an argument
# explantion of exactly what the script does please see at the README.txt
# Author: Peter Manev
# Released under GNU GPL v2

input=$1
ARGS=1         # Script requires 1 arguments.
#E_BADARGS=85   # Wrong number of arguments passed to script.
ERR_CODE=0     #defaulting to success return to the OS

echo -e "\n Supplied directory is:  $input \n";

  if [ $# -ne "$ARGS" ];
    then
      echo -e "\n USAGE: `basename $0` the script requires one argument - directory."
      echo -e "\n Please supply a directory containing pcap file that has a corresponding rule."
      exit 1;
  fi
#above check if valid number of arguments are passed to the script - 
#should be 1 (directory location)

 if [ ! -d "$input" ]; then
     # Control will enter here if DIRECTORY doesn't exist
     echo "The supplied directory does not exist or the name is wrong !"
     exit 1;
 fi


#below we check if the configurational file exists and 
#load the $SURICATA and $CONFIG values from there
if [ -f regression_config ];then 
	. regression_config
  else
  echo " \"regression_config \" NOT FOUND !! !"
  exit 1;
fi

# We check also if the provided yaml and binary exist in the system
if [ ! -f "$SURICATA" ];then
  echo "The provided file $SURICATA NOT FOUND !!"
  exit 1;
fi

if [ ! -f "$CONFIG" ];then
  echo "The provided file $CONFIG NOT FOUND !!"
  exit 1;
fi


time_of_run=`date +"%F-%T"`
`touch "$PWD"/regression-run-"$time_of_run".log`
regression_log_file="$PWD"/regression-run-"$time_of_run".log


echo "==== RUNNING TESTS WITH ===>" >> $regression_log_file
`$SURICATA --build-info >> $regression_log_file `
echo -e "\n\n\n" >> $regression_log_file

SUCCESS="0"
FAILURE="0"

for pcap_file in  $( dir $input -1 |grep .pcap$ ); do

pcap_name="$(echo "$pcap_file" |awk -F "." ' { print $1 } ')"
[[ "$pcap_name" =~  ^([0-9]*)-([0-9]*)-([a-zA-Z0-9_]*)-(public|private|PUBLIC|PRIVATE)-(tp|fp)-([0-9]*)$ ]] && : || echo "The pcap file name has the wrong standard. you should use something like 2002031-001-sandnet-public-tp-01.pcap " exit 1;
#the above 2 lines checks for a valid pcap name , 
#it is basically an if else statement.


TMP_LOG=`mktemp -d /tmp/suriqa.XXXXXXXXXX` #creating a tmp log name 
`mkdir $TMP_LOG/files` 
# making a "files" directory, just in case if magic files are 
#enabled in yaml, so that we do not stop suri from execution. 


rule_id="$(echo "$pcap_file" |awk -F "." ' { print $1 } ' |awk -F "-" '{ print $1 }' )"
pcap_id="$(echo "$pcap_file" |awk -F "." ' { print $1 } ' |awk -F "-" '{ print $2 }' )"
pcap_source="$(echo "$pcap_file" |awk -F "." ' { print $1 } ' |awk -F "-" '{ print $3 }' )"
#
privacy="$(echo "$pcap_file" |awk -F "." ' { print $1 } ' |awk -F "-" '{ print $4 }' )"
tp_fp="$(echo "$pcap_file" |awk -F "." ' { print $1 } ' |awk -F "-" '{ print $5 }' )"
exp_alerts="$(echo "$pcap_file" |awk -F "." ' { print $1 } ' |awk -F "-" '{ print $6 }' )"

if [ ! -f "$input/$rule_id.rules" ];
then
    echo "File \"$rule_id.rules\"  corresponding to $pcap_file not found! " \
    | tee -a $regression_log_file
    let ERR_CODE=$ERR_CODE+1 ;
    exit $ERR_CODE ;
fi
# the above if statement checks for a corresponding rules file 
#to the pcap supplied

$SURICATA -c $CONFIG --runmode=single -S $input/$rule_id.rules -r $input/$pcap_file -l $TMP_LOG/ &> /dev/null 
#run Suricata

number_of_alerts="$(cat $TMP_LOG/fast.log |grep \:$rule_id\: |wc -l)"
#count the number of alerts with that particular rules files SID

if [ "$exp_alerts" -ne "$number_of_alerts" ];
  then
    
    echo $rule_id ": FAILED, see $TMP_LOG, rulefile: $rule_id.rules, pcap file $pcap_file. Expected $exp_alerts, got $number_of_alerts." \
    | tee -a $regression_log_file
    let FAILURE=$FAILURE+1 ;
    
  else
    echo $rule_id ": OK" | tee -a $regression_log_file
    let SUCCESS=$SUCCESS+1;
    ` rm -r $TMP_LOG `
    #above removing the temp log directory ONLY if the test has SUCCEEDED
fi

done

echo; echo "SUMMARY:" | tee -a $regression_log_file
echo "-----------" | tee -a $regression_log_file
echo "SUCCESS: " $SUCCESS | tee -a $regression_log_file
echo "FAILURE: " $FAILURE | tee -a $regression_log_file

 [[ $FAILURE -eq "0" ]] && exit 0 || exit 1
#the upper line - if failures are 0 it returns success, 
#otherwise error to the  OS


