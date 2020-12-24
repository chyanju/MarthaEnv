# MarthaEnv
Static Analysis Guided Interactive Environment for Android

# ApkInstrumentor
  * `git clone git@github.com:chyanju/MarthaEnv.git && cd ApkInstrumentor`

### Dump Jimple IR
  * `./gradlew run --args="AndroidLogger dump /path/to/the/apk"`
  * Output in `ApkInstrumentor/demo/Android`

### Instrument Apk
  * `./gradlew run --args="AndroidLogger instrument /path/to/the/apk /path/to/the/training/json /path/to/the/test/json"`
  * instrumented apk will be stored in : `ApkInstrumentor/demo/Android`

### Sign and install the apk
  * `cd ApkInstrumentor/demo/Android`
  * `./sign.sh path/to/the/instrumented/apk key "android"`
  * `adb install -r -t /path/to/the/signed/apk`
