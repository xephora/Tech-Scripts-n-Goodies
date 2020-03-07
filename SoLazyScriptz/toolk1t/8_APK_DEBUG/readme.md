# Section for Debugging APK's

### Unpacking Unzipfiles
```
unzip file.jar
```

### decompiling class files
```
jad -d . -s java -r file.class

-d output destination
-s source type
-r restore package directory structure
