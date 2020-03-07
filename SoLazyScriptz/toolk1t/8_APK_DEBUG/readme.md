# Section for Debugging APK's

### Unzipping jar files
```
unzip file.jar
```

### decompiling class files
```
jad -d . -s java -r file.class

-d output destination
-s source type
-r restore package directory structure
