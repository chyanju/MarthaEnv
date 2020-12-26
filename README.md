# MarthaEnv
Static Analysis Guided Interactive Environment for Android

# ApkInstrumentor
  * require jdk version 12
  * `git clone git@github.com:chyanju/MarthaEnv.git && cd ApkInstrumentor`
  * build the test app apk and put it `/path/to/app.apk`

### Dump Jimple IR
  * `./gradlew run --args="AndroidLogger dump /path/to/app.apk"`
  * Output in `ApkInstrumentor/demo/Android`

### Instrument Apk
  * `./gradlew run --args="AndroidLogger instrument /path/to/app.apk /path/to/train.json /path/to/test.json"`
  * instrumented apk will be stored in : `ApkInstrumentor/demo/Android/Instrumented/app.apk`

### Sign and install the apk
  * `cd ApkInstrumentor/demo/Android`
  * `./sign.sh path/to/instrumented.apk key "android"`
  * `adb install -r -t /path/to/signed.apk`

# Neural Agent

### simple0.apk



