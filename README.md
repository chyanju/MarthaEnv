# MarthaEnv
Static Analysis Guided Interactive Environment for Android

# ApkInstrumentor
  * require jdk version 12
  * `git clone git@github.com:chyanju/MarthaEnv.git && cd ApkInstrumentor`
  * build the test app apk and put it `/path/to/app.apk`

### Dump Jimple IR
  * `./gradlew run --args="AndroidLogger dump /path/to/app.apk /path/to/the/output-dir"`
  * Output in `/path/to/the/output-dir`

### Instrument Apk using test and training data
  * `./gradlew run --args="AndroidLogger instrument /path/to/app.apk /path/to/train.json /path/to/test.json /path/to/the/output-dir"`
  * instrumented apk will be stored in : `/path/to/the/output-dir`
  
### Auto instrument sensitive APIs
  * `./gradlew run --args="AndroidLogger auto_instrument /path/to/app.apk /path/to/the/output-dir"`
  * instrumented apk will be stored in : `/path/to/the/output-dir`

### Auto instrument using builtin jar
  * `cd ApkInstrumemtor && java -cp build/libs/CombinedJar-all.jar dev.navids.soottutorial.Main AndroidLogger auto_instrument /path/to/app.apk /path/to/the/output-dir`

### Sign and install the apk
  * `cd ApkInstrumentor/demo/Android`
  * `./sign.sh path/to/instrumented.apk key "android"`
  * `adb install -r -t /path/to/signed.apk`
  
### Running uiautomator helper
  *`/home/priyanka/research/projects/MarthaEnv/uiautomator_helper/main.py -p /path/to/the/apk -o /path/to/the/output/directory -w /path/to/the/directory/where/wtg.dot/is/present -gs /path/to/the/goal/json`

# Neural Agent

### simple0.apk



