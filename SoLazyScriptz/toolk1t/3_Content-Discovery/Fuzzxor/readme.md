How Batch Fuzzing Works

--Python Script to run

fuzz_batch.py

Enter URL: https://examplewebsite/path/

--List of Paths to fuzz (Find them from either fuzzing the root directory or passive burp hits)

fuzzlist.txt
paths
to
fuzz

--Execute the pythonscript and watch each path gets fuzzed automatically.
fuzz_path.py

Scanning for 43,000 items within wordlist all.txt
ffuff scans https://examplewebsite/path/paths/FUZZ

Scanning for 43,000 items within wordlist all.txt
ffuff scans https://examplewebsite/path/to/FUZZ

Scanning for 43,000 items within wordlist all.txt
ffuff scans https://examplewebsite/path/fuzz/FUZZ
