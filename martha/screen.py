import matplotlib.pyplot as plt
import xml.etree.ElementTree as ET
import numpy as np
from saveScreen import ScreenData
import math
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
        self.fixedChannels = None
        self.bitRepresentation = None

    def buildAttribHash(self, root):
        for child in root:
            for att in child.attrib:
                if att not in self.attribHash:
                    self.attribHash[att] = []
                if child.attrib[att] == "true":
                    self.attribHash[att].append(child)
            self.buildAttribHash(child)
    
    def packageAsScreenData(self):
        self.setRelevantComponents(["clickable"])
        self.buildScreenFromComponents()
        self.createComponentChannels()
        totalElements = len(self.relevantComponents)
        numChannels = len(self.screenChannels)
        compInChannel = []
        tileInChannel = []
        for channel in self.screenChannels:
            compInChannel.append(len(channel))
            self.computeTileDimensions(channel)
            tileInChannel.append(self.tileDimensions)
        return ScreenData(self.xmlstr,totalElements,numChannels,tileInChannel,compInChannel)
        
        
        return ScreenData(self.xmlstr,...)
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
            if elem is None:
                continue
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
    
    def buildTiledScreen(self, components=None):
        if components is None:
            components = self.relevantComponents
        tileScreen = np.full(self.tileDimensions, None)
        for comp in components:
            bounds = self.parseBounds(comp.attrib["bounds"])
            w = int((bounds.x1/self.width)*self.tileDimensions[1]) 
            h = int((bounds.y1/self.height)*self.tileDimensions[0])
            if tileScreen[h][w] is None:
                tileScreen[h][w]=[]
            tileScreen[h][w].append(comp)
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
        if bound1.x2 >= bound2.x1 and bound1.x2 <= bound2.x2:
            if bound1.y2 >= bound2.y1 and bound1.y2 <= bound2.y2:
                return True
        if bound1.x2 >= bound2.x1 and bound1.x2 <= bound2.x2:
            if bound1.y1 >= bound2.y1 and bound1.y1 <= bound2.y2:
                return True
        if bound1.x1 >= bound2.x1 and bound1.x1 <= bound2.x2:
            if bound1.y2 >= bound2.y1 and bound1.y2 <= bound2.y2:
                return True
        


        if bound2.x1 >= bound1.x1 and bound2.x1 <= bound1.x2:
            if bound2.y1 >= bound1.y1 and bound2.y1 <= bound1.y2:
                return True
        if bound2.x2 >= bound1.x1 and bound2.x2 <= bound1.x2:
            if bound2.y2 >= bound1.y1 and bound2.y2 <= bound1.y2:
                return True
        if bound2.x2 >= bound1.x1 and bound2.x2 <= bound1.x2:
            if bound2.y1 >= bound1.y1 and bound2.y1 <= bound1.y2:
                return True
        if bound2.x1 >= bound1.x1 and bound2.x1 <= bound1.x2:
            if bound2.y2 >= bound1.y1 and bound2.y2 <= bound1.y2:
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
            screenChannels = sorted(screenChannels,key=len)
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


    def checkTopLeftIntersects(self, point, bound):
        if point.x1 > bound.x1 and point.x1 < bound.x2:
            if point.y1 > bound.y1 and point.y1 < bound.y2:
                return True
        return False
    

    def showTileOverlay(self):
        print(self.tileScreen.flatten().shape)
        flatTile = self.tileScreen.flatten()
        components = []
        for tile in flatTile:
            if tile is None:
                continue
            for elem in tile:
                components.append(elem)
        tileTemp = self.buildGeneralScreenFromComponents(components)
        for i in range(self.tileDimensions[0]):
            tileTemp[:,(i*(self.height//self.tileDimensions[0]))] = np.ones((self.width,))*255
        for i in range(self.tileDimensions[1]):
            tileTemp[i*(self.width//self.tileDimensions[1])] = np.ones((1,self.height))*255
        self.showScreen(tileTemp)


    def getBoundsObject(self, width, height, tempBounds):
        topLeftx = tempBounds.x1-width if (tempBounds.x1 - width > 0) else 0
        topLefty = tempBounds.y1 - height if (tempBounds.y1 -height > 0) else 0
        bottomRightx = tempBounds.x1 + width if (tempBounds.x1+ width < self.width) else self.width
        bottomRighty = tempBounds.y1 + height if (tempBounds.y1+height < self.height) else self.height
        tempArea = Bounds(topLeftx, bottomRightx, topLefty, bottomRighty)
        return tempArea

    def computeTileDimensions(self, components = None):
        if components is None:
            components = self.relevantComponents
        if len(components) <= 1:
            self.setTileDimensions((1,1))
            #print(tileHorizontal)
            #print(tileVertical)
            return
        print("NUMBER OF COMPONENTS")
        print(len(components))
        xbounds = {}
        ybounds = {}
        for component in components:
            xbounds[component] = [self.width]
            ybounds[component] = [self.height]
            tempBounds = self.parseBounds(component.attrib["bounds"])
            for component2 in components:
                if component == component2:
                    continue
                bounds2 = self.parseBounds(component2.attrib["bounds"])
                xbounds[component].append(abs(tempBounds.x1-bounds2.x1))
                ybounds[component].append(abs(tempBounds.y1-bounds2.y1))
        maxArea = -1
        maxes = []
        minMaxArea = None
        minMaxWidth = None
        maxXBounds = []
        maxYBounds = []
        minMaxHeight = None
        for elem in xbounds.keys():
            maxArea = -1
            maxWidth = 0
            maxHeight = 0
            tempBounds = self.parseBounds(elem.attrib["bounds"])
            for i in range(len(xbounds[elem])):
                for j in range(len(ybounds[elem])):
                    width = xbounds[elem][i]
                    height = ybounds[elem][j]
                    tempArea = self.getBoundsObject(width, height, tempBounds)
                    valid = True
                    for comp in components:
                        if comp == elem:
                            continue
                        if self.checkTopLeftIntersects(self.parseBounds(comp.attrib["bounds"]), tempArea):
                            valid = False
                            break

                    if valid:
                        if maxArea == -1:
                            maxArea = width*height
                            maxWidth = width
                            maxHeight = height
                        elif maxArea < width*height:
                            maxArea = width*height
                            maxWidth = width
                            maxHeight = height
            maxXBounds.append(maxWidth)
            maxYBounds.append(maxHeight)
           # if minMaxArea is None: 
           #     if maxArea != -1:
           #         minMaxArea = maxArea
           #         minMaxWidth = maxWidth
           #         minMaxHeight = maxHeight
           # elif minMaxArea > maxArea and maxArea != -1:
           #     minMaxArea = maxArea
           #     minMaxWidth = maxWidth
           #     minMaxHeight = maxHeight
        maxArea = None
        maxX = None
        maxY = None
        for x in maxXBounds:
            for y in maxYBounds:
                valid = True
                for comp in components:
                    tempBounds = self.parseBounds(comp.attrib["bounds"])
                    for compAgainst in components:
                        if comp == compAgainst:
                            continue
                        tempArea = self.getBoundsObject(x,y,tempBounds)
                        valid = not self.checkTopLeftIntersects(self.parseBounds(compAgainst.attrib["bounds"]), tempArea)
                        if not valid:
                            break
                    if not valid:
                        break
                if valid:
                    if maxArea is None:
                        maxArea = x*y
                        maxX = x
                        maxY = y
                    elif maxArea < x*y:
                        maxArea = x*y
                        maxX = x
                        maxY = y

        tileHorizontal = (self.width + maxX -1)//maxX
        tileVertical = (self.height+maxY -1)//maxY
        self.setTileDimensions((tileVertical, tileHorizontal))
        print(tileHorizontal)
        print(tileVertical)

    def createFixedChannels(self,components=None):
        if self.fixedChannels is None:
            print("Number of channels not set yet")
            return
        if components is None:
            components = self.relevantComponents
        screenChannels = []
        for i in range(self.fixedChannels):
            screenChannels.append([])
        for comp in components:
            bounds = self.parseBounds(comp.attrib["bounds"])
            Truedist = None
            for i in range(len(screenChannels)):
                dist = None
                for j in range(len(screenChannels[i])):
                    x=self.calcDistance(self.parseBounds(comp.attrib["bounds"]),self.parseBounds(screenChannels[i][j].attrib["bounds"]))
                    if dist is None or dist > x:
                        dist = x
                        
                if dist is None:
                    Truedist = (-1,i)
                    break
                
                if Truedist is None or Truedist[0] <dist:
                    Truedist = (dist,i)
            screenChannels[Truedist[1]].append(comp)
        self.screenChannels = screenChannels
        #for screen in screenChannels:
        #    self.screenChannels.append(self.buildGeneralScreenFromComponents(screen))


    def calcDistance(self,bounds1, bounds2):
        return math.sqrt((bounds1.x1-bounds2.x1)**2+(bounds1.y1-bounds2.y1)**2)

    def checkValidTiling(self):
        for i in self.tileScreen:
            for j in i:
                if j is None:
                    continue
                if len(j) > 1:
                    return False
        return True

    def checkValidScreenRepresentation(self):
        if self.fixedChannels is None or self.fixedChannels <= 0:
            print("Invalid Channels") 
            return None
        if self.tileDimensions is None:
            print("Invalid Tile dimensions")
            return None
        b = True
        for i in self.screenChannels:
            self.buildTiledScreen(i)
            b = self.checkValidTiling()
            if b == False:
                break
        return b



    def outputBitRepresentation(self):
        if self.fixedChannels is None or self.fixedChannels == 0:
            print("Invalid Channels")
            return None
        if self.tileDimensions is None:
            print("Invalid Tile Dimensions")
            return None

        self.bitRepresentation = np.zeros((self.fixedChannels, self.tileDimensions[0],self.tileDimensions[1]))
        for i in range(self.fixedChannels):
            self.buildTiledScreen(self.screenChannels[i])
            for j in range(len(self.tileScreen)):
                for k in range(len(self.tileScreen[j])):
                    if self.tileScreen[j][k] is None:
                        continue
                    self.bitRepresentation[i][j][k] = len(self.tileScreen[j][k])
        return self.bitRepresentation

        
