import glob
import numpy as np
from saveScreen import ScreenData
import matplotlib.pyplot as plt
from screen import ScreenObject
class ScreenDataParser:
    def __init__(self, files):
        self.files = files
        self.tileCoordinates = None
        self.tileCoordinatesHorizontal = None
        self.tileCoordinatesVertical = None
        self.numberOfChannels = None

   
    def queryTileDimensions(self):
        self.tileCoordinates = []
        self.tileCoordinatesHorizontal = []
        self.tileCoordinatesVertical = []
        for f in self.files:
            data = ScreenData.deSerialize(f)
            for t in data.tilesPerChannel:
                self.tileCoordinates.append(t)
                self.tileCoordinatesVertical.append(t[0])
                self.tileCoordinatesHorizontal.append(t[1])
                

    def graphAllTileDimensions(self):
        if self.tileCoordinates is None:
            self.queryTileDimensions()
        plt.scatter(self.tileCoordinatesHorizontal, self.tileCoordinatesVertical)
        plt.show()


    def queryNumChannels(self):
        self.numberOfChannels = []
        for f in self.files:
            data = ScreenData.deSerialize(f)
            self.numberOfChannels.append(data.numChannels)

    def graphAllChannelsPerScreen(self):
        if self.numberOfChannels is None:
            self.queryNumChannels()
        data = self.numberOfChannels
        plt.hist(data, bins=range(min(data), max(data) + 1, 1))
        plt.show()
    def checkValidTiling(self,fixedChannels = 5, fixedTile = (20,10)):
        numValid = 0
        total = 0
        for f in self.files:
            data1 = ScreenData.deSerialize(f)
            data = ScreenObject(data1.xmlString,1440,2960)
            data.fixedChannels = fixedChannels
            data.tileDimensions = fixedTile
            data.setRelevantComponents(["clickable"])
            data.buildScreenFromComponents()
            data.fixedChannels = fixedChannels
            data.createFixedChannels()
            bval = 1
            for channel in data.screenChannels:
                data.buildTiledScreen(channel)
                if not data.checkValidTiling():
                    bval = 0
                    print("_____________")
                    print(data1.numScreenComponents)
                    s=np.max(data.screen)/(255//len(data.relevantComponents))
                    print(s)
#                    if s < 5:
#                        data.buildScreenFromComponents()
#                        data.showScreen()
                    print("_____________")
                    #data.showScreenChannels()
                    data.buildTiledScreen(channel)
                    data.showTileOverlay()
                    break
            numValid+=bval
            total+=1
        print("TOTAL NUMBER OF SCREENS VALID " + str(numValid))
        print("TOTAL NUMBER OF SCREENS " + str(total))


if __name__ == "__main__":
    files = glob.glob("./*.json")
    parser = ScreenDataParser(files)
    parser.graphAllTileDimensions()
    parser.graphAllChannelsPerScreen()
    parser.checkValidTiling(10,(20,40))
