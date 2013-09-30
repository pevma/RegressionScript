
Released under GNU GPL v2

THIS IS WHAT THE SCRIPT DOES:

It is to be used for regression tests for Suricata IDPS -
http://suricata-ids.org/
 
 It takes in 1 argument - a directory where a pcap/rule pairs of files exist. 
 Like so -
 2002031-001-sandnet-public-tp-01.pcap
 2002031.rules
 
 ###
 The name of the pcap will be in this format:
 
 2002031-001-sandnet-public-tp-01.pcap
 meaning:
 
 2002031 - rule id (sid)
 001 - pcap id (for having multiple pcaps for a sid)
 sandnet - pcap source
 public - whether or not the pcap can be shared
 tp - true positive (fp for false positive)
 01 - number of alerts we should see for the sid
 
 ###
 The rule file should be in the this format:
 
 2002031.rules
 
 ###
 The goal is simple. The script should run the pcap against the rules and
 check if the number/sid of alerts is correct. If it isn't, display an
 error/warning.
 
 ###
 After the script is done it will generate a textfile based report 
 in the directory where it was run from. 
 Example -  regression-run-2013-09-30-16:44:21.log
 It will also include the Suricata revision/version it was run 
 with at the top of the report. 
 
 ###
 To run the script:
 ./regression_script.sh /path/to/directory/with/rule/pcap/pairs
