#!/bin/bash
adb shell killall -9 frida-server
adb shell /data/local/tmp/frida-server &