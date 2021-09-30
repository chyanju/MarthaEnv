#!/bin/bash

# Need to install zipalign, apksigner, 

#soot-4.2.1-jar-with-dependencies.jar from https://repo1.maven.org/maven2/org/soot-oss/soot/4.2.1/

#android.jar from https://github.com/Sable/android-platforms/blob/master/android-21/android.jar

#key file created by
#keytool -genkey -v -keystore my.keystore -keyalg RSA -keysize 2048 -validity 10000 -alias app


if [ -z "$1" ]
then
	echo "Usage: $0 apk-name"
	echo "Usage: $0 apk-name install"
	exit
else
	APK_PATH=$1
fi

APK=$(basename $APK_PATH)


# https://github.com/soot-oss/soot/issues/528
# I couldn't get -cp to work
export CLASSPATH=".:$PWD/soot-4.2.1-jar-with-dependencies.jar"

javac AndroidInstrument.java || exit

# Soot doesn't run if the output file already exists
rm -rf sootOutput/

# -allow-phantom-refs to prevent crashing, from https://github.com/soot-oss/soot/issues/284, not entirely sure if I should
java AndroidInstrument -android-jars "$ANDROID_SDK_ROOT/platforms" -process-dir "$APK_PATH" -allow-phantom-refs || exit

# At this point, the instrumented APK is in sootOutput/
# The following steps are just to sign, install, and run it

if [ "$2" == "install" ]
then
	zipalign -p -f -v 4 sootOutput/"$APK" aligned.apk || exit
	echo password | apksigner sign --ks my.keystore aligned.apk || exit
	#install -r doesn't work if signature changed
	#adb uninstall com.example.app
	adb install -r -t aligned.apk || exit
	#clear log
	adb logcat -c
	echo "Running adb logcat"
	adb logcat -e SOOT
fi

