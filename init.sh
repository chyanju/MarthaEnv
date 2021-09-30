#!/bin/bash

APK_PATH=$1
APK=$(basename $APK_PATH)

cd tests/backend/instrument/
./run.sh $APK_PATH || exit
zipalign -p -f -v 4 sootOutput/"$APK" aligned.apk || exit
echo password | apksigner sign --ks my.keystore aligned.apk || exit
cd ../../..

cd martha
python callgraph.py $APK_PATH || exit
python layout.py $APK_PATH || exit

python ../example0.py ../tests/backend/instrument/aligned.apk || exit
