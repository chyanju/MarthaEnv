import glob
from saveScreen import ScreenData
files = glob.glob("./*.json")

for f in files:
    data = ScreenData.deSerialize(f)
    print("______________________")
    print(data.numChannels)
    print(data.tilesPerChannel)
    print(data.elementsInChannel)
    print("______________________")
