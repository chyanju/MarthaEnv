appPath=$1
outPutDir=$2
retargaterJar=$3
androidJar=$4
ic3Jar=$5


forceAndroidJar=$androidJar
rm -rf testspace
mkdir testspace

appName=`basename $appPath .apk`
retargetedPath=testspace/$appName.apk/retargeted/retargeted/$appName

rm -rf output/ic3/$appName.txt

java -Xmx8192m -jar $retargaterJar $forceAndroidJar $appPath $retargetedPath
java -Xmx8192m -jar $ic3Jar -apkormanifest $appPath -input $retargetedPath -cp $forceAndroidJar -protobuf $outPutDir

rm -rf testspace
rm -rf sootOutput