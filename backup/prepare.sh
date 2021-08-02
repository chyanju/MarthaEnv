#!/bin/bash

INSTDIR="/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/ApkInstrumentor/"
APPDIR="/Users/joseph/Desktop/UCSB/20summer/MarthaEnv/test/com.github.cetoolbox_11/"

OAPP="original.apk"
OTRAIN="is_simple0.json"
OTEST="is_test.json"

EXPAPP="app_simple0.apk"
# better not change these names
TMPTRAIN="tmp_train.json"
TMPTEST="tmp_test.json"

# make a copy
cd $APPDIR
cp ./$OAPP ./$EXPAPP
# add keywords to file (Logger depends on "train" and "test" file keywords)
cp ./$OTRAIN ./$TMPTRAIN
cp ./$OTEST ./$TMPTEST

# instrument
cd $INSTDIR
./gradlew run --args="AndroidLogger dump $APPDIR/$EXPAPP"
./gradlew run --args="AndroidLogger instrument $APPDIR/$EXPAPP $APPDIR/$TMPTRAIN $APPDIR/$TMPTEST"
rm $APPDIR/$TMPTRAIN
rm $APPDIR/$TMPTEST

# sign
cd $INSTDIR/demo/Android/
./sign.sh $INSTDIR/demo/Android/Instrumented/$EXPAPP key "android"

cp $INSTDIR/demo/Android/Instrumented/$EXPAPP $APPDIR/
rm $INSTDIR/demo/Android/Instrumented/$EXPAPP
adb install -r -t $APPDIR/$EXPAPP
