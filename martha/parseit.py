import matplotlib
import xml.etree.ElementTree as ET
from screen import ScreenObject
from saveScreen import ScreenData

f = open("xmldoc10.txt", "r")
print(f.readline())
print(f.readline())
xmldict = {}
tempstr = ""
for line in f:
    if (line == "_________________\n"):
        xmldict[tempstr] = 0
        tempstr = ""
    else:
        tempstr += line
#screenStuff = ScreenData("HUBBABUBBA", 20, 3, [(4,3),(8,7),(1,3)], [8,5,7])
#print(type(screenStuff))
#screenStuff.serialize()
#print("Serialize done")
#whatsit = ScreenData.deSerialize("HUBBABUBBA.json")
#print("Deserialize done")
#print(type(whatsit))

for i in xmldict.keys():
#    break
    xmldict[i] = ET.fromstring(i)
    screen = ScreenObject(i, 1440, 2960)
    data = screen.packageAsScreenData()
    data.serialize()
#    continue
#    screen.buildAbstractScreenFromAttrib(["clickable","visible-to-user"])
    screen.setRelevantComponents(["clickable"])
    #screen.setTileDimensions((2,2))
    screen.buildScreenFromComponents()
    screen.showScreen()
    screen.fixedChannels = 5
    screen.createFixedChannels()
    screen.showScreenChannels()
    screen.tileDimensions = (20,10)
    v = screen.outputBitRepresentation()
    screen.checkValidScreenRepresentation()
    print(v)
    for channel in screen.screenChannels:
#        screen.computeTileDimensions(channel)
        screen.buildTiledScreen(channel)
        screen.showTileOverlay()
    break
#        if screen.checkValidTiling():
#            print("YEAH BABY")
#        else:
#            print("AWWWW")
#    print("????????")
#    print(type(screen.screenChannels[0][0]))
#    print(screen.screenChannels[0][0])
#    print("????????")
#    for channel in screen.screenChannels:
#        screen.computeTileDimensions(channel)
#        screen.buildTiledScreen(channel)
#        screen.showTileOverlay()
    #screen.computeTileDimensions(screen.screenChannels[0])
    #screen.buildTiledScreen(screen.screenChannels[0])
    #screen.showTileOverlay()
    #screen.createComponentChannels(screen.tileScreen[2][2])
    #screen.createComponentChannels()
   # screen.showScreenChannels()
 #   screen.buildScreenFromComponents()
#    screen.createComponentChannels()
#    screen.showScreenChannels()
#    break
#    screen.buildTiledScreen()
#    for k in range(3):
#        for j in range(3):
#            screen.showTileinScreen((k,j))

#for i in xmldict.keys():
#    for elem in xmldict[i]:
#        print(elem.tag, elem.attrib)
#        for att in elem.attrib:
#            print(att)
#            print(elem.attrib[att])
#        print("????????")
#        for tag in elem:
#            print(tag)
#        print(elem.attrib["bounds"])
#        print(elem.attrib["bounds"][0])


