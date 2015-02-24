import threading
import subprocess
import sys
import time

iii = 0
click_run = 0
ylist=[]

class FuncThread(threading.Thread):
    def __init__(self, target, *args):
        self._target = target
        self._args = args
        threading.Thread.__init__(self)

    def run(self):
        self._target(*self._args)
 
# def anotherFunc():
#     process = subprocess.Popen(["click node_gatewayselector.click MESH_IFNAME=mesh0 MESH_IP_ADDR=192.168.42.148 MESH_ETH= MESH_NETWORK=192.168.42.0/24 FAKE_IP=10.0.0.1 FAKE_ETH=1A-2B-3C-4D-5E-6F FAKE_NETWORK=10.0.0.1/24"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
#     global y
#     global iii
#     # Poll process for new output until finished

#     while True:
#         nextline = process.stdout.readline()
#         if nextline == '' and process.poll() != None:
#             break
        
#         sys.stdout.write(nextline)
#         sys.stdout.flush()
        
#         iii+=1
#         if not iii%100000:
#             iii+=1
#             lock.acquire()                
#             print "Adding to y"
#             y+="192.168.42.6,ba:43:22:33:ba:bd,200\n"
#             lock.release()

#    output = process.communicate()[0]
#    exitCode = process.returncode

#    if (exitCode == 0):
#        return output
#    else:
#        raise ProcessException(command, exitCode, output)

# # Example usage
# def someOtherFunc(data, key):
#         process = subprocess.Popen(["find"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
#         while True:
#             nextline = process.stdout.readline()
#             if nextline == '' and process.poll() != None:
#                 break

# #            arr.append(nextline)
# #            print "appended"
#             lock.acquire()
#             y.append("192.168.42.6,ba:43:22:33:ba:bd,200")
#             sys.stdout.write(nextline)
#             lock.release()
#             sys.stdout.flush()
                
#         output = process.communicate()[0]
#         exitCode = process.returncode

#         if (exitCode == 0):
#             print arr
#             return output
#         else:
#             raise ProcessException(command, exitCode, output)

# #    while 1:
# #        print "someOtherFunc was called : data=%s; key=%s" % (str(data), str(key))

# -*- coding: utf-8 -*-

import wx
import wx.lib.buttons
import SpeedMeter as SM
from math import pi, sqrt

wx.SetDefaultPyEncoding('iso8859-1')

#----------------------------------------------------------------------
# Beginning Of Nodeman Demo wxPython Code
#----------------------------------------------------------------------

class SpeedMeterDemo(wx.Frame):
    def __init__(self):
        wx.Frame.__init__(self, None, -1, "Nodeman Demo",
                         wx.DefaultPosition,
                         size=(400,400),
                         style=wx.DEFAULT_FRAME_STYLE |
                          wx.NO_FULL_REPAINT_ON_RESIZE)

        self.statusbar = self.CreateStatusBar(2, wx.ST_SIZEGRIP)
        self.statusbar.SetStatusWidths([-2, -1])
        # statusbar fields
        statusbar_fields = [("Nodeman @ BITS Quark 2014. Check out the Bandwidth Meter!")]
        
        for i in range(len(statusbar_fields)):
            self.statusbar.SetStatusText(statusbar_fields[i], i)
        
        self.SetMenuBar(self.CreateMenuBar())
        
        panel = wx.Panel(self, -1)
        sizer = wx.BoxSizer(wx.VERTICAL)

        panel1 = wx.Panel(panel, -1)
        panel2 = wx.Panel(panel, -1)

        panel.SetBackgroundColour(wx.BLACK)
        panel1.SetBackgroundColour(wx.BLACK)
#        panel.Refresh()
        # First SpeedMeter: We Use The Following Styles:
        #
        # SM_DRAW_HAND: We Want To Draw The Hand (Arrow) Indicator
        # SM_DRAW_SECTORS: Full Sectors Will Be Drawn, To Indicate Different Intervals
        # SM_DRAW_MIDDLE_TEXT: We Draw Some Text In The Center Of SpeedMeter
        # SM_DRAW_SECONDARY_TICKS: We Draw Secondary (Intermediate) Ticks Between
        #                          The Main Ticks (Intervals)

        self.SpeedWindow1 = SM.SpeedMeter(panel1,
                                          extrastyle=SM.SM_DRAW_HAND |
                                          SM.SM_DRAW_SECTORS |
                                          SM.SM_DRAW_MIDDLE_TEXT |
                                          SM.SM_DRAW_SECONDARY_TICKS,
#                                          SM.SM_DRAW_GRADIENT,
                                          size=(1366,500)
                                          )

        # Set The Region Of Existence Of SpeedMeter (Always In Radians!!!!)
        self.SpeedWindow1.SetAngleRange(-pi/8, 9*pi/8)

        # Create The Intervals That Will Divide Our SpeedMeter In Sectors        
        intervals = range(0, 2001, 400)
        self.SpeedWindow1.SetIntervals(intervals)

        # Assign The Same Colours To All Sectors (We Simulate A Car Control For Speed)
        # Usually This Is Black
        colours = [wx.BLACK]*5

        self.SpeedWindow1.SetIntervalColours(colours)
        self.SpeedWindow1.SetSpeedBackground((0,0,0))

        # Assign The Ticks: Here They Are Simply The String Equivalent Of The Intervals
        ticks = [str(interval) for interval in intervals]
        #ticks = ['400']#,'800','1200','1600','2000']

        self.SpeedWindow1.SetTicks(ticks)
        # Set The Ticks/Tick Markers Colour
        self.SpeedWindow1.SetTicksColour((0,160,0))
        # We Want To Draw 5 Secondary Ticks Between The Principal Ticks
        self.SpeedWindow1.SetNumberOfSecondaryTicks(5)

        # Set The Font For The Ticks Markers
        self.SpeedWindow1.SetTicksFont(wx.Font(20, wx.SWISS, wx.NORMAL, wx.BOLD))
                                       
        # Set The Text In The Center Of SpeedMeter
#        self.SpeedWindow1.SetMiddleText("KB/s")
        # Assign The Colour To The Center Text
#        self.SpeedWindow1.SetMiddleTextColour(wx.BLUE)
        # Assign A Font To The Center Text
#        self.SpeedWindow1.SetMiddleTextFont(wx.Font(60, wx.SWISS, wx.NORMAL, wx.BOLD))

        # Set The Colour For The Hand Indicator
        self.SpeedWindow1.SetHandColour(wx.Colour(255,50 , 0))

        # Do Not Draw The External (Container) Arc. Drawing The External Arc May
        # Sometimes Create Uglier Controls. Try To Comment This Line And See It
        # For Yourself!
        self.SpeedWindow1.DrawExternalArc(False)

        # Set The Current Value For The SpeedMeter
        self.SpeedWindow1.SetSpeedValue(0)

        # Draw The Icon In The Center Of SpeedMeter        
#        self.SpeedWindow1.SetMiddleIcon(iconxyzzy)        

        # End Of SpeedMeter Controls Construction. Add Some Functionality

        self.helpbuttons = []
        self.isalive = 0
        
        # These Are Cosmetics For The First SpeedMeter Control
        bsizer1 = wx.BoxSizer(wx.VERTICAL)

        bsizer1.Add(self.SpeedWindow1, 1, wx.EXPAND)
        panel1.SetSizer(bsizer1)

        self.timer = wx.PyTimer(self.ClockTimer)

        #Label
#        self.t2 = wx.StaticText(panel, -1, "404 Not Found", style=wx.ALIGN_CENTRE)

        panel2.SetBackgroundColour(wx.BLACK)
        font = wx.Font(100, wx.FONTFAMILY_DEFAULT,wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
        self.txt1337 = wx.StaticText(panel2, -1, "", pos=(10,10))
        self.txt1337.SetFont(font)

#        center = wx.StaticText(panel, -1, "align center", (100, 50), (160, -1), wx.ALIGN_CENTER)
#        center.SetForegroundColour(wx.BLACK)
#        center.SetBackgroundColour(wx.RED)

        image_file = 'wn.jpg'
        bmp1 = wx.Image(image_file, wx.BITMAP_TYPE_ANY).ConvertToBitmap()
        # image's upper left corner anchors at panel coordinates (0, 0)
        self.bitmap1 = wx.StaticBitmap(self, -1, bmp1, (0, 0))

        # show some image details
        str1 = "%s  %dx%d" % (image_file, bmp1.GetWidth(), bmp1.GetHeight()) 

        #Create the list_ctrl here for gate list display
        self.list_ctrl = wx.ListCtrl(panel2, size=(100,200), style=wx.LC_REPORT | wx.LC_NO_HEADER)

        self.list_ctrl.SetFont((wx.Font(15, wx.SWISS, wx.NORMAL, wx.BOLD)))
        self.list_ctrl.SetBackgroundColour(wx.BLACK)
        self.list_ctrl.SetForegroundColour(wx.RED)

        self.list_ctrl.InsertColumn(0, 'Gate IP', width = 200)
        self.list_ctrl.InsertColumn(1, 'Eternet Address', width = 240)
        self.list_ctrl.InsertColumn(2, 'Link Speed', width=200)
        self.list_ctrl.InsertStringItem(0, 'Gate IP');
        self.list_ctrl.SetStringItem(0, 1, 'Ethernet');
        self.list_ctrl.SetStringItem(0, 2, 'Speed(KB/s)');
        
        # self.currvalue = 0
        bsizer2 = wx.BoxSizer(wx.HORIZONTAL)
        bsizer2.Add(self.bitmap1, 1)
        bsizer2.Add(self.list_ctrl, 1)

        panel2.SetSizerAndFit(bsizer2)
        sizer.Add(panel1, 1, wx.EXPAND | wx.ALL, 20)
        sizer.Add(panel2, 1, wx.EXPAND)        

        panel.SetSizerAndFit(sizer)
        sizer.Layout()

        self.timer.Start(1000)        
        self.Bind(wx.EVT_CLOSE, self.OnClose)

    def ExitWindow(self, event):

        if hasattr(self, "popup"):
            self.popup.Destroy()
            del self.popup
            self.selectedbutton.SetToggle(False)

        self.isalive = 0
        
    def ClockTimer(self):
        # if self.currvalue >= 59:
        #     self.currvalue = 0
        # else:
        #     self.currvalue = self.currvalue + 1                

        #Format of nodelog.log is IPv4,Eth,LinkSpeed

        # x = open("nodelog.log", 'r')
        # y = x.read()        
        # x.close()

        global click_run
        global ylist
        # process = ""
        
        # if click_run == 0:
        #     click_run = 1
        #     process = subprocess.Popen(["click node_gatewayselector.click MESH_IFNAME=mesh0 MESH_IP_ADDR=192.168.42.100 MESH_ETH=c4:6e:1f:11:c1:e9 MESH_NETWORK=192.168.42.0/24 FAKE_IP=10.0.0.1 FAKE_ETH=1A-2B-3C-4D-5E-6F FAKE_NETWORK=10.0.0.1/24"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # while True:
        #     nextline = process.stdout.readline()
        #     if nextline == '' and process.poll() != None:
        #         break
        
        #     sys.stdout.write(nextline+"PYTHONED!")
        #     sys.stdout.flush()

        #     if nextline[0]=='-':
        #         ylist.remove(nextline[1:])
        #     elif nextline not in ylist:
        #         ylist.append(nextline)
                
        #     #Need to add 

        # #ylist = y.split('\n')[:-1]
        
        total_speed = 1000

        self.list_ctrl.DeleteAllItems()
        self.list_ctrl.InsertStringItem(0, 'Gate IP');
        self.list_ctrl.SetStringItem(0, 1, 'Ethernet');
        self.list_ctrl.SetStringItem(0, 2, 'Speed(KB/s)');

        i = 0
        for entry in ylist:
            x = entry.split(',')
            print x
            self.list_ctrl.InsertStringItem(i+1, str(i+1));
            self.list_ctrl.SetStringItem(i+1, 0, x[0]);
            self.list_ctrl.SetStringItem(i+1, 1, x[1]);
            self.list_ctrl.SetStringItem(i+1, 2, x[2]);

            #110314 via 149
            total_speed += int(x[2])
            i+=1
            
        self.SpeedWindow1.SetSpeedValue(total_speed)
        self.txt1337.SetLabel(str(total_speed) + " KB/s")

#        self.txt1337.SetLabel("9999" + " KB/s")
#        self.list_ctrl.InsertStringItem(0, "Xyzzy");
#        self.list_ctrl.InsertStringItem(1, "Xyzzy");
#        self.list_ctrl.InsertStringItem(2, "Xyzzy");     
#        print "ClockTimer() called."
#        self.SpeedWindow2.SetMiddleText(str(self.currvalue) + " s")            
#        self.SpeedWindow2.SetSpeedValue(self.currvalue/5.0)
        
    def OnClose(self, event):

        try:
            self.timer.Stop()
            del self.timer
        except:
            pass        
        
        self.Destroy()


    def OnAbout(self, event):

        msg = "NodeMan @ BITS Quark GOA! 2015.\n Created by SCAR.\n For more information, find scar1337 on github."
              
        dlg = wx.MessageDialog(self, msg, "SpeedMeter Demo",
                               wx.OK | wx.ICON_INFORMATION)
        dlg.SetFont(wx.Font(8, wx.NORMAL, wx.NORMAL, wx.NORMAL, False, "Verdana"))
        dlg.ShowModal()
        dlg.Destroy()
        

    def CreateMenuBar(self):

        file_menu = wx.Menu()
        
        SM_EXIT = wx.NewId()        
        file_menu.Append(SM_EXIT, "&Exit")
        self.Bind(wx.EVT_MENU, self.OnClose, id=SM_EXIT)

        help_menu = wx.Menu()

        SM_ABOUT = wx.NewId()        
        help_menu.Append(SM_ABOUT, "&About...")
        self.Bind(wx.EVT_MENU, self.OnAbout, id=SM_ABOUT)

        menu_bar = wx.MenuBar()

        menu_bar.Append(file_menu, "&File")
        menu_bar.Append(help_menu, "&Help")        

        return menu_bar        
        
def startup():
    app = wx.PySimpleApp()
    frame = SpeedMeterDemo()
    frame.Show()
    frame.Maximize()
    app.MainLoop()



#t1 = FuncThread(someOtherFunc, [1,2], 6)
startup();
