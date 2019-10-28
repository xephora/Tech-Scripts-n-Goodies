# Fuzzxor

The following script will use automate the use of wfuzz commands to make scanning much quicker.

## Prerequisites

OS: Linux

1.
The script requires Seclists wordlists for this to work. More information: (https://github.com/danielmiessler/SecLists)
```
git clone https://github.com/danielmiessler/SecLists
```
2.
The script needs to look for its fuzzer scripts.
```
cd root
mkdir pwn
cd pwn
copy all fuzzer scripts to that directory.
```
The next step is optional.
```
cp /root/Tech-Scripts-n-Goodies/SoLazyScriptz/Fuzzer* ~/pwn
```

3.
Ensure you have the Ruby Lib 'bundler'. After cloning go to the directory of Fuzzxor and type the following.
```
gem install bundler
```
If you already have bundler proceed with installing the lib.
```
bundle install
```
