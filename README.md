# MarthaEnv
Static Analysis Guided Interactive Environment for Android

# ApkInstrumentor
  * require jdk version 12
  * `git clone git@github.com:chyanju/MarthaEnv.git && cd ApkInstrumentor`
  * build the test app apk and put it `/path/to/app.apk`

### Dump Jimple IR
  * `./gradlew run --args="AndroidLogger dump /path/to/app.apk"`
  * Output in `ApkInstrumentor/demo/Android`

### Instrument Apk using test and training data
  * `./gradlew run --args="AndroidLogger instrument /path/to/app.apk /path/to/train.json /path/to/test.json"`
  * instrumented apk will be stored in : `ApkInstrumentor/demo/Android/Instrumented/app.apk`
  
### Auto instrument sensitive APIs
  * `./gradlew run --args="AndroidLogger auto_instrument /path/to/app.apk"`
  * instrumented apk will be stored in : `ApkInstrumentor/demo/Android/Instrumented/app.apk`

### Auto instrument using builtin jar
  * `cd ApkInstrumemtor && java -cp build/libs/CombinedJar-all.jar dev.navids.soottutorial.Main AndroidLogger auto_instrument /path/to/app.apk`

### Sign and install the apk
  * `cd ApkInstrumentor/demo/Android`
  * `./sign.sh path/to/instrumented.apk key "android"`
  * `adb install -r -t /path/to/signed.apk`
  
### Running uiautomator helper
  *`/home/priyanka/research/projects/MarthaEnv/uiautomator_helper/main.py -p /path/to/the/apk -o /path/to/the/output/directory -w /path/to/the/directory/where/wtg.dot/is/present -gs /path/to/the/goal/json`

# Neural Agent

### simple0.apk



