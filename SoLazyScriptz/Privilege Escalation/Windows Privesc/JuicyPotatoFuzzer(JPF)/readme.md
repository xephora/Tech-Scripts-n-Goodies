# Juicy Potato Fuzzer

I've designed a script that will automatically check CLSIDs that are OS specific. Whichever CLSIDs are successful just utilize those.  
  
### Requires:  
JuicyPotato  
https://github.com/ohpe/juicy-potato  
https://github.com/ohpe/juicy-potato/releases  
  
Helpful resources that helped me create this script  
https://hunter2.gitbook.io/darthsidious/privilege-escalation/juicy-potato

### Usage

```
1. .\jpf_fuzzer.bat
2. Choose your OS
3. Whichever Succeeds are successful hits
4. You can then execute whatever using those CLSIDs.
```

```
Side Note:

I only chose NT Authority\System CLSIDs, if there's a need to add other accounts feel free to add an issue.
```
