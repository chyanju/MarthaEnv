#!/bin/bash

INSTDIR="/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/ApkInstrumentor/"
APPDIR="/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/test/"

OAPP="ultrasonic-debug.apk"
EXPAPP="out.ultrasonic-debug.apk"

# make a copy
cd $APPDIR
cp ./$OAPP ./$EXPAPP

# # instrument
cd $INSTDIR
# ./gradlew run --args="AndroidLogger dump $APPDIR/$EXPAPP"
# ./gradlew run --args="AndroidLogger auto_instrument $APPDIR/$EXPAPP"
java -cp build/libs/CombinedJar-all.jar dev.navids.soottutorial.Main AndroidLogger auto_instrument $APPDIR/$EXPAPP

# sign
cd $INSTDIR/demo/Android/
./sign.sh $INSTDIR/demo/Android/Instrumented/$EXPAPP key "android"

cp $INSTDIR/demo/Android/Instrumented/$EXPAPP $APPDIR/
rm $INSTDIR/demo/Android/Instrumented/$EXPAPP
adb install -r -t $APPDIR/$EXPAPP
