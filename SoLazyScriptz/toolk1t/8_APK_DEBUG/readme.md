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

Thank you to mr dee-see for these commands! Amazing and clean output!
grep -r --include=*.java keyword .
find . -name '*java*' | xargs grep keyword

Another great query provided by dee-see
grep -roaP '[a-zA-Z0-9_.-]+\.amazonaws\.com(/[a-zA-Z0-9_.-]+)?'
grep -roaP '[a-zA-Z0-9_.-]+\.storage\.googleapis\.com(/[a-zA-Z0-9_.-]+)?'

Discovery of buckets
Test if bucket can be registered
Test write access

If Google bucket is accessible
Test privilege access on bucket:
https://www.googleapis.com/storage/v1/b/<bucket_name>
https://www.googleapis.com/storage/v1/b/<bucket name>/iam/testPermissions
```
Source information regarding bug hunting buckets: https://is.muni.cz/th/de05t/master_thesis_final.pdf

### Getting App Name and Pulling App using adb
```
adb shell pm path <app.name>
adb  pull <full.path.of.app.name>
```

### APK Hunting scripts
After you decompile the apk, you can use the following scripts. Ensure the scripts are located in the same directory as your decompiled apk.
```
scrape_apk_data
scrape_urls

./scrape_apk_data
./scrape_urls
```
