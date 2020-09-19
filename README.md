<div align="left">
  <h2>
    <img src="./icon.png" width=30>
  	MarthaEnv
  </h2>
</div>

A Static Analysis Guided Interactive Environment for Android.

## Prototype Flow

When analyzing an app with the Martha Environment, make sure it is running on the indicated device (in its startup page). This will ensure that the initial local state matches the start state determined by GATOR in the global graph.

This framework uses two main tools: GATOR for creating a global graph of the given app, and UIAutomator for local state detection and interacting with UI elements as they are encountered.

Once you've followed the set up instructions below, you can run the `test_script` to see an example of each currently-implemented function. As a note, this script looks for some features specific to the `ValidRec` app (namely, looking for a specific button when testing `take_action`). The APK for this app is provided for testing purposes, or the script can be modified to interact with a different app as necessary.

First, the user must pass the script the serial number for the device or emulator the app is being run on, the path to the GATOR executable, and the path to the target app's APK file. You can get the serial number of the emulated device you want to use by running `adb devices`

GATOR is run on the provided APK, then dumps the window transition graph of the app to a `dot` file which is then parsed into an `MGraph` object, which represents the global graph of the app. 

The `MGraph` is then passed as a parameter to an `MEnvironment` instance, along with the `Device` object connected to the Android device with the given serial number. 

Right now, the `get_available_actions` returns a list of all possible "click" actions that can be taken on the current page as `MActions`- this action list can be expanded to contain more types of actions (long-clicks, drags, etc) using the UIAutomator API. An `MAction` consists of a _subject_- a `UIObject` returned by UIAutomator's search for Android Widget objects- and an _action_ - a lambda function that triggers the desired action on the subject (clicking, in this case).

The `take_action` function takes an `MAction` object and triggers the action on the subject. Right now, the global GATOR graph is not synced to the local state information from UIAutomator, but once it is this function should also update the `current_state` of the environment's `global_graph`. For example, if `take_function` is called to click the button called `NEXT`, it should also examine the global graph to see if there are any edges from the current state to a different state that are triggered by this action. If any such edge is found, the graph's `current_state` should be updated to be the destination state of that edge, if the action is completed successfully.

The `get_current_device_state` function gets an XML dump of the current view on the device and gets the name of the current running activity using `adb` calls, and returns a new `MState` object containing that information. 

## Setup

You'll need at least 4 components to get started:
   * Android SDK (install with Android Studio)
   * Android Debug Bridge (ADB)
   * UIAutomator (Python wrapper)
   * GATOR (static analyzer for Android)

### Android SDK

Install Android Studio (https://developer.android.com/studio/install), and make sure you have the appropriate platform files for the API level of the app you are trying to analyze. If you don't have the proper SDK platform files, the GATOR analyzer will fail with a message indicating the level you are missing, which can then be installed with the SDK Manager built into Android Studio. For example, if you need to analyze an app with API levl 25, you should go to the Tools-> SDK Manager menu in Android Studio, click the button next to the `Android 7.1.1` package, and hit Apply to install.

As a side note, the Soot library that GATOR relies on for static analysis has trouble with API levels 30 and up, so make sure any app you are examining is at level 29 or lower. Make sure to check the API level of the app first if you run into any long errors from GATOR.

### Android Debug Bridge

Make sure you have `adb` installed, which allows for direct interaction with the Android device from the command line. It is required for at least one function in the `MEnvironment` class. On Linux, you should be able to use `sudo apt-get install adb`.

### UIAutomator

UIAutomator is a testing framework that provides an API for interacting directly with an app on an Android device (or emulator, more likely). We're using it to automate the interaction with UI elements detected on the running app.

This project uses the Python wrapper of UIAutomator implemented here, with installation instructions in the README: https://github.com/xiaocong/uiautomator 

You can read the documentation for the original Java UIAutomator library here: https://developer.android.com/training/testing/ui-automator

### GATOR

The official site for the GATOR analyzer is here: http://web.cse.ohio-state.edu/presto/software/gator/ 

When you download the latest release, it should come with a HOWTO file which gives instructions on setting up and using the analyzer. The main thing to note is that the Martha Environment uses a simple custom client- `WTGDumpClient`- to get the dot file of the app's window transition graph. A copy of this client is provided in this repo, but the GATOR binary _must_ be recompiled after the client file is moved to the proper location in the GATOR directory.

Make sure that the `python` command is aliased to Python3 when running GATOR.

### Other Notes
To use the WTGDumpClient to generate a WTG dot file from GATOR, place the provided `WTGDumpClient.java` file in the `gator/sootandroid/src/main/java/presto/android/gui/clients` directory and rebuild the GATOR executable with `./gator b`

The provided `validrec_sample.apk` is a small app with 3 buttons on the first page, one of which triggers a transition between the app's 2 activities. The `validrec_sample_graph.png` file is what the graph generated by GATOR from this APK should look like.