#!/bin/bash
#Requires Seclists
#Install:
#git clone https://github.com/danielmiessler/SecLists
#Fuzzxor automates and uses wfuzz commands


x=0
while [ $x = 0 ]
do

	clear
	echo 'Fuzzxor tool - Choose your Fuzzxor options'
	echo 'Fuzz Quickscan {1}'
	echo 'Fuzz Fullscan {2}'
	echo 'Fuzz IIS {3}'
	echo 'Fuzz PHP {4}'
	echo 'Fuzz LDAP {5}'
	echo 'Fuzz LFI {6}'
	echo 'Fuzz using cookie custom wordlist {7}'
	echo 'Fuzz Post Request {8}'
	read sel

	case "$sel" in
		1)
		clear
		echo 'Fuzzxor Quickscan'
		/root/pwn/fuzzer_quickhits
		x=1
		;;
		2)
		clear
		echo 'Fuzzxor Fullscan'
		/root/pwn/fuzzer
		x=1
		;;
		3)
		clear
		echo 'Fuzzxor Scan IIS'
		/root/pwn/fuzzer_IIS
		x=1
		;;
		4)
		clear
		echo 'Fuzzxor Scan PHP'
		/root/pwn/fuzzer_php
		x=1
		;;
		5)
		clear
		echo 'Fuzzxor Scan LDAP'
		/root/pwn/fuzzer_LDAP
		x=1
		;;
		6)
		clear
		echo 'Fuzzxor Scan LFI'
		/root/pwn/fuzzer_LFI
		x=1
		;;
		7)
		clear
		echo 'Fuzzxor Custom Scan with Cookie'
		/root/pwn/fuzzer_customscan_withcookie
		x=1
		;;
		8)
		clear
		echo 'Fuzzxor Post Request'
		/root/pwn/fuzzer_postrequest
		x=1
		;;
	esac
done



