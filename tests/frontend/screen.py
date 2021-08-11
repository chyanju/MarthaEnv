import matplotlib.pyplot as plt
import xml.etree.ElementTree as ET
import numpy as np


class Bounds:
    def __init__(self,x1,x2,y1,y2):
        self.x1 = x1
        self.x2 = x2
        self.y1 = y1
        self.y2 = y2

class ScreenObject:
    def __init__(self, xmlstr, width, height):
        self.xmlstr = xmlstr
        self.xmlElemTree = ET.fromstring(self.xmlstr)
        self.width = width
        self.height = height
        self.screen = np.zeros((width, height))
        self.attribHash = {}
        self.buildAttribHash(self.xmlElemTree)
        self.GRAYSCALE = 255
        self.tileDimensions = (3,3)
        self.tileScreen = None
        self.relevantComponents = []
        self.screenChannels = None

    def buildAttribHash(self, root):
        for child in root:
            for att in child.attrib:
                if att not in self.attribHash:
                    self.attribHash[att] = []
                if child.attrib[att] == "true":
                    self.attribHash[att].append(child)
            self.buildAttribHash(child)

    def setRelevantComponents(self, attrib):
        components = []
        firstAssign = True
        if len(attrib) == 0:
            print("No attributes passed")
            return
        for i in range(len(attrib)):
            if attrib[i] not in self.attribHash:
                print(str(attrib[i]) + " is not a Valid attribute")
                continue
            if firstAssign:
                components = set(self.attribHash[attrib[i]])
                firstAssign = False
            else:
                components = set(self.attribHash[attrib[i]]) & components
        self.relevantComponents = components
    
    def buildScreenFromComponents(self):
        self.screen = self.buildGeneralScreenFromComponents() 
    def buildGeneralScreenFromComponents(self, components =None):
        if components is None:
            components = self.relevantComponents
        if len(components) == 0:
            print("No components on this screen have these attribute set to true")
            return None
        screen = np.zeros((self.width, self.height))
        scale = self.GRAYSCALE//len(components)
        for elem in components:
            bounds = self.parseBounds(elem.attrib["bounds"])
            for i in range(bounds.x1,bounds.x2):
                for j in range(bounds.y1,bounds.y2):
                    screen[i][j] += scale
        return screen

    def parseBounds(self, bounds):
        tempstr = ""
        boundsdict = {}
        firstNumeric = 0
        for i in bounds:
            if not i.isnumeric():
                if firstNumeric == 0:
                    continue
                elif tempstr != "":
                    boundsdict[firstNumeric] = int(tempstr)
                    tempstr = ""
                    firstNumeric+=1
            else:
                if firstNumeric == 0:
                    firstNumeric +=1
                tempstr += i
        if len(boundsdict.keys()) != 4:
            print("Invalid Bounds string")
            return None
        else:
            return Bounds(boundsdict[1], boundsdict[3], boundsdict[2], boundsdict[4])

    def showScreen(self, screen = None):
        if screen is None:
            screen = self.screen
        plt.imshow(screen.T, cmap='gray_r', vmin=0, vmax=255)
        plt.show()

    def setTileDimensions(self, dimensionTuple):
        self.tileDimensions = dimensionTuple
    
    def buildTiledScreen(self):
        tileScreen = np.full(self.tileDimensions, None)
        for comp in self.relevantComponents:
            bounds = self.parseBounds(comp.attrib["bounds"])
            if tileScreen[int((bounds.x1/self.width)*self.tileDimensions[0])][int((bounds.y1/self.height)*self.tileDimensions[1])] is None:
                tileScreen[int((bounds.x1/self.width)*self.tileDimensions[0])][int((bounds.y1/self.height)*self.tileDimensions[1])]=[]
            tileScreen[int((bounds.x1/self.width)*self.tileDimensions[0])][int((bounds.y1/self.height)*self.tileDimensions[1])].append(comp)
        self.tileScreen = tileScreen
    
    def showTileinScreen(self, tileTuple):
        if self.tileScreen[tileTuple[0]][tileTuple[1]] is None:
            print("This tile is empty")
            return
        tileTemp = self.buildGeneralScreenFromComponents(self.tileScreen[tileTuple[0]][tileTuple[1]])
        self.showScreen(tileTemp)

    def checkIntersect(self, bound1, bound2):
        if bound1.x1 >= bound2.x1 and bound1.x1 <= bound2.x2:
            if bound1.y1 >= bound2.y1 and bound1.y1 <=bound2.y2:
                return True
        elif bound2.x1 >= bound1.x1 and bound2.x1 <= bound1.x2:
            if bound2.y1 >= bound1.y1 and bound2.y1 <= bound1.y2:
                return True
        return False

    def createComponentChannels(self, components = None):
        if components is None:
            components = self.relevantComponents
        screenChannels = []
        for comp in components:
            added = False
            bounds = self.parseBounds(comp.attrib["bounds"])
            for i in range(len(screenChannels)):
                intersects = False
                for j in range(len(screenChannels[i])):
                    if self.checkIntersect(self.parseBounds(comp.attrib["bounds"]),self.parseBounds(screenChannels[i][j].attrib["bounds"])):
                        intersects = True
                        break
                if not intersects:
                    screenChannels[i].append(comp)
                    added = True
                    break
            if not added:
                screenChannels.append([])
                screenChannels[-1].append(comp)
        self.screenChannels = screenChannels
        #for screen in screenChannels:
        #    self.screenChannels.append(self.buildGeneralScreenFromComponents(screen))

    def showScreenChannels(self):
        if self.screenChannels is None:
            print("Channels have not been created yet for this screen")
        screenChannels = []
        for screen in self.screenChannels:
            screenChannels.append(self.buildGeneralScreenFromComponents(screen))
        border = np.full((self.height,2), self.GRAYSCALE)
        screen = None
        print("NUMBER OF CHANNELS: "+ str(len(screenChannels)))
        for i in range(len(screenChannels)):
            if screen is None:
                screen = np.copy(screenChannels[i]).T
            else:
                screen = np.concatenate((screen, border), axis=1)
                screen = np.concatenate((screen, screenChannels[i].T), axis=1)
        plt.imshow(screen, cmap='gray_r', vmin=0, vmax=255)
        plt.show()




