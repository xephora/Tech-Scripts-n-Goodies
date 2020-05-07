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
```

### jadx to decompile apk
```
jadx -d /absolute/path/to/outdir /absolute/path/to/file.apk
```

### Hunting for interesting items
```
Review the android manifest
resources/AndroidManifest.xml

From the root directory
find . | grep FileName
find . | grep .java | more
find . | grep .xml 
find . | grep main
find . | grep Main
find . | grep activity
find . | grep Activity
```
