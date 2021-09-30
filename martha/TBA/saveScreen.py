import math
import json
from datetime import datetime
class ScreenData:
    
    def deSerialize(ScreenObjJsonFile):
        try:
            data = None
            with open('./'+ScreenObjJsonFile, 'r') as f:
                data =  json.load(f)
            if data is not None:
                return ScreenData(data['xmlString'],data['numScreenComponents'],data['numChannels'],data['tilesPerChannel'],data['elementsInChannel'])
            else:
                return None
        except Exception as e:
            print(e)
            return None
    def __init__(self, xmlString, numScreenComponents, numChannels, tilesPerChannel, elementsInChannel):
        self.xmlString = xmlString
        self.numScreenComponents = numScreenComponents
        self.numChannels = numChannels
        self.tilesPerChannel = tilesPerChannel
        self.elementsInChannel = elementsInChannel
    
    def serialize(self):
        try:
            serializableDict = {}
            serializableDict['xmlString'] = self.xmlString
            serializableDict['numScreenComponents'] = self.numScreenComponents
            serializableDict['numChannels'] = self.numChannels
            serializableDict['tilesPerChannel'] = self.tilesPerChannel
            serializableDict['elementsInChannel'] = self.elementsInChannel
            with open('./'+str(datetime.now())+'.json', 'w') as f:
                json.dump(serializableDict, f)
        except Exception as e:
            print("Could not serialize data")
            print(e)
    def getXMLString(self):
        return self.xmlString

    def getTotalComponents(self):
        return self.numScreenComponents

    def getNumChannels(self):
        return self.numChannels

    def getTilesPerChannel(self):
        return self.tilesPerChannel

    def getElementsInChannels(self):
        return self.elementsInChannel
