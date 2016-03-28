import fcntl, easygui, logging, time, urllib, urllib2, sys, simplejson, ttk, multiprocessing, Queue, os, netifaces
from Tkinter import *
from threading import *
from PIL import Image, ImageTk
from netfilter import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

inc_txt_str = " "
out_txt_str = " "
inc_packet = 0
inc_packet_size = 0.0
out_packet = 0
out_packet_size = 0.0
pSniff = 0
pParse = 0
pVT = 0
subdirectory = "IPDB"
subdirectory1="Icons"
wl = ['google', 'dropbox', 'facebook', 'valve', 'amazon', 'apple']
bl = ['tk', 'crack', 'xxx', 'hack', 'crack']

if not os.path.exists(os.path.join(subdirectory)):
    os.makedirs(os.path.join(subdirectory))
with open(os.path.join(subdirectory, "parseip.db"), "a") as parse_ip:
	parse_ip.write("")
with open(os.path.join(subdirectory, "blacklist.db"), "a") as parse_ip:
	parse_ip.write("")
with open(os.path.join(subdirectory, "whitelist.db"), "a") as parse_ip:
	parse_ip.write("")
with open(os.path.join(subdirectory, "greylist.db"), "a") as parse_ip:
	parse_ip.write("")

def exitClick(main_win):
	main_win.destroy()
	main_win.quit()
	sys.exit()
	
def optionsON():
	global pauseButton,listframe,whiteButton,blackButton,greyButton
	pauseButton=Button(border_buttons1,text="Pause",command=pauseSniff)
	pauseButton.pack(side="left",ipadx=10,pady=7)
	listframe=Frame(parse_win)
	whiteButton=Button(listframe,text="Clear Whitelist", command=clearWhitelist)
	whiteButton.grid(row=0, column=0, ipadx=10,pady=7)
	blackButton=Button(listframe,text="Clear Blacklist", command=clearBlacklist)
	blackButton.grid(row=0, column=2, ipadx=10,pady=7)
	greyButton=Button(listframe,text="Clear Greylist", command=clearGreylist)
	greyButton.grid(row=0, column=4,ipadx=10,pady=7)
	listframe.grid(row=4, column=0, columnspan=3)
	if Omenu.entrycget(0,"state")==NORMAL:
		Omenu.entryconfigure(0,state=DISABLED)
	
	if Omenu.entrycget(2,"state")==DISABLED:
		Omenu.entryconfigure(2,state=NORMAL)

def clearWhitelist():
	#os.remove(os.path.join(subdirectory, "whitelist.db")
	with open(os.path.join(subdirectory, "whitelist.db"), "w") as parse_ip:
		parse_ip.write("")
	whiteltext.configure(state=NORMAL)
	whiteltext.delete(1.0,END)
	whiteltext.configure(state=DISABLED)
	
def clearBlacklist():
	#os.remove(os.path.join(subdirectory, "whitelist.db")
	with open(os.path.join(subdirectory, "blacklist.db"), "w") as parse_ip:
		parse_ip.write("")
	blackltext.configure(state=NORMAL)
	blackltext.delete(1.0,END)
	blackltext.configure(state=DISABLED)
	
def clearGreylist():
	#os.remove(os.path.join(subdirectory, "whitelist.db")
	with open(os.path.join(subdirectory, "greylist.db"), "w") as parse_ip:
		parse_ip.write("")
	greyltext.configure(state=NORMAL)
	greyltext.delete(1.0,END)
	greyltext.configure(state=DISABLED)
	
def optionsOFF():
	pauseButton.pack_forget()
	listframe.destroy()
	if Omenu.entrycget(0,"state")==DISABLED:
		Omenu.entryconfigure(0,state=NORMAL)
		
	if Omenu.entrycget(2,"state")==NORMAL:
		Omenu.entryconfigure(2,state=DISABLED)
	

def pauseSniff():
	thrSniff.stahp()
	if pauseButton["text"]=="Pause":
		pauseButton["text"]="Resume"
	pauseButton.configure(command=resumeSniff)
	
def resumeSniff():
	global pSniff
	pSniff = 0
	if pauseButton["text"]=="Resume":
		pauseButton["text"]="Pause"
	pauseButton.configure(command=pauseSniff)
	
def hideClick():
	parse_win.withdraw()	

def pauseparsing():
	prog.stop()
	prog_stat.set(str("Status: Parsing stopped"))
	image1=Image.open(os.path.join(subdirectory1,"Play.png"))
	image1=image1.resize((90,90), Image.BICUBIC)
	photo1=ImageTk.PhotoImage(image1)
	startstopButton.configure(command=resumeparsing, image=photo1)
	startstopButton.image=photo1
		
def resumeparsing():
	prog.start(50);
	prog_stat.set(str("Status: Parsing in progress"))
	image1=Image.open(os.path.join(subdirectory1,"Pause.png"))
	image1=image1.resize((90,90), Image.BICUBIC)
	photo1=ImageTk.PhotoImage(image1)
	startstopButton.configure(command=pauseparsing, image=photo1)
	startstopButton.image=photo1

		
		
def ipTables():
	#GUI
	iptable= Toplevel()
	iptable.title("System IP Table")
	iptable.resizable(1,1)
	iptable.withdraw()
	iptable.deiconify()
	iptable_frame= Frame(iptable)
	iptable_frame.grid(row=3, columnspan=3)
	iptable_textbox = Text(iptable_frame,width=screen_width/20,height=screen_height/30, bg="white", fg="black", state="normal")
	iptable_textbox.pack(fill=BOTH, expand=YES, side="left")
	
	
	table = iptc.Table(iptc.Table.FILTER)
	chain = iptc.Chain(table, 'OUTPUT')
	for rule in chain.rules:
			(packets, bytes) = rule.get_counters()
			print packets, bytes
	for chain in table.chains:
		print "======================="
		print "Chain ", chain.name
		for rule in chain.rules:
			print "Rule", "proto:", rule.protocol, "src:", rule.src, "dst:", rule.dst, "in:", rule.in_interface, "out:", rule.out_interface,
			print "Matches:",
			for match in rule.matches:
				print match.name,
			print "Target:",
			print rule.target.name
	print "======================="

def aboutClick():
	about_win = Toplevel()
	about_win.title("About")
	about_win.resizable(1,1)
	about_win.withdraw()
	about_win.deiconify()
	about_frame=Frame(about_win)
	about_frame.grid(row=3,columnspan=3)
	about_textbox = Text(about_frame, width=screen_width/20,height=screen_height/30, bg="black", fg="green", state="normal")
	about_textbox.pack(fill=BOTH, expand=YES, side="left")
	about_text="\n\n\tHH   HH IIIII DDDDD   PPPPPP   SSSSS\n\tHH   HH  III  DD  DD  PP   PP SS     \n\tHHHHHHH  III  DD   DD PPPPPP   SSSSS \n\tHH   HH  III  DD   DD PP           SS\n\tHH   HH IIIII DDDDDD  PP       SSSSS \n\n   The Heuristic Intrusion Detection and Prevention System\n\n\nA lightweight, intelligent security suite for your linux servers\nVersion: 0.1\nVisit http://www.vaptlab.com/HIDPS\n\nCreated by:\nKirit Sankar Gupta\nDiptarshi Sen\nPiyali Gupta"
	about_textbox.insert(END, about_text)
	about_textbox.configure(state=DISABLED)

def parseUI():
	global parse_win, parseips, prog_stat, startstopButton, tpi, prog_label, prog, spi, whitel, whiteltext, whitescroll, blackl, blackltext, blackscroll, greyl, greyltext, greyscroll
	parse_win = Toplevel()
	parse_win.title("Parsing IPs")
	parse_win.resizable(1,1)
	#parse_win.overrideredirect(True)
	parse_win.withdraw()
	parseips = Frame(parse_win)
	parse_win._offsetx = 0
	parse_win._offsety = 0
	parse_win.protocol('WM_DELETE_WINDOW', parse_win.withdraw)
	
	tpi = Text(parseips, width=screen_width/12, height=screen_height/50, bg="black", fg="white")
	tpi.pack(fill=BOTH, expand=YES, side="left")
	parseips.grid(row=0,column=0, columnspan=3, sticky=NW)
	with open(os.path.join(subdirectory, "parseip.db"), 'r') as piList:
		addtoPI = piList.read()
		tpi.configure(state=NORMAL)
		tpi.insert(END, addtoPI)
		tpi.see(END)
		tpi.update_idletasks()
		tpi.configure(state=DISABLED)
	
	whitel= Frame(parse_win) 
	whiteltext= Text(whitel, width=screen_width/32, height=screen_height/45, bg="white", fg="black")
	whiteltext.pack(fill=BOTH, expand=YES, side="left")
	whitescroll = Scrollbar(whitel)
	whitescroll.pack(side="right", fill="y")
	whitescroll.config(command=whiteltext.yview)
	whiteltext.config(yscrollcommand=whitescroll.set)
	whitel.grid(row=3,column=0, sticky=W)
	with open(os.path.join(subdirectory, "whitelist.db"), 'r') as wlList:
		addtoWL = wlList.read()
		whiteltext.configure(state=NORMAL)
		whiteltext.insert(END, addtoWL)
		whiteltext.see(END)
		whiteltext.update_idletasks()
		whiteltext.configure(state=DISABLED)
	
	blackl= Frame(parse_win)
	blackltext= Text(blackl, width=screen_width/32, height=screen_height/45, bg="black", fg="white")
	blackltext.pack(fill=BOTH, expand=YES, side="left")
	blackscroll = Scrollbar(blackl)
	blackscroll.pack(side="right", fill="y")
	blackscroll.config(command=blackltext.yview)
	blackltext.config(yscrollcommand=blackscroll.set)
	blackl.grid(row=3,column=1, sticky=E)
	with open(os.path.join(subdirectory, "blacklist.db"), 'r') as blList:
		addtoBL = blList.read()
		blackltext.configure(state=NORMAL)
		blackltext.insert(END, addtoBL)
		blackltext.see(END)
		blackltext.update_idletasks()
		blackltext.configure(state=DISABLED)
	
	
	greyl= Frame(parse_win)
	greyltext= Text(greyl, width=screen_width/32, height=screen_height/45, bg="grey", fg="red")
	greyltext.pack(fill=BOTH, expand=YES, side="left")
	greyscroll = Scrollbar(greyl)
	greyscroll.pack(side="right", fill="y")
	greyscroll.config(command=greyltext.yview)
	greyltext.config(yscrollcommand=greyscroll.set)
	greyl.grid(row=3,column=2, sticky=E)
	with open(os.path.join(subdirectory, "greylist.db"), 'r') as glList:
		addtoGL = glList.read()
		greyltext.configure(state=NORMAL)
		greyltext.insert(END, addtoGL)
		greyltext.see(END)
		greyltext.update_idletasks()
		greyltext.configure(state=DISABLED)
	
	#buttonsGUI
	image1=Image.open(os.path.join(subdirectory1,"Play.png"))
	image1=image1.resize((90,90), Image.BICUBIC)
	photo1=ImageTk.PhotoImage(image1)
	button_frame = Frame(parseips)
	startstopButton = Button(button_frame, compound=TOP, width=90,height=90, image=photo1, command=resumeparsing)
	startstopButton.image=photo1
	startstopButton.grid(row=2,column=3)
	
	image2=Image.open(os.path.join(subdirectory1,"Hide.png"))
	image2=image2.resize((90,90), Image.BICUBIC)
	photo2= ImageTk.PhotoImage(image2)
	hidebutton = Button(button_frame,command=hideClick,compound=TOP,width=90, height=90, image=photo2)
	hidebutton.image=photo2
	hidebutton.grid(row=4,column=3)
	button_frame.pack(side="right")
	
	spi = Scrollbar(parseips)
	spi.pack(side="right", fill="y")
	spi.config(command=tpi.yview)
	tpi.config(yscrollcommand=spi.set)
	
	s=ttk.Style()
	s.theme_use('clam')
	s.configure("red.Horizontal.TProgressbar", foreground='red', background='red')
	prog= ttk.Progressbar(parse_win, style="red.Horizontal.TProgressbar", mode='indeterminate', orient='horizontal', length=500, maximum=50)
	prog_stat = StringVar()
	#prog_stat = "Parsing stopped"
	prog_label = Label(parse_win, borderwidth=2,height=1,width=60, font='verdana 10', textvariable=prog_stat);
	prog_label.grid(row=2,column=0, columnspan=3)
	prog.grid(row=1, column=0, columnspan=3)
	
def parseClick ():
	global thrVT
	parse_win.deiconify()
	thrVT = Thread(target=vtLookup, args=("http://executivecoaching.co.il",))
	thrVT.start()
	
def vtLookup (testIP):
	url = "https://www.virustotal.com/vtapi/v2/url/scan"
	#testIP = "http://executivecoaching.co.il"
	parameters = {"url": testIP, "apikey": "95c948ffe8c50d27b0087b71c04c1b0ccf074007fe7fa0bc48bf4094063d7088"}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = response.read()
	response_dict = simplejson.loads(json)
	scan_id = response_dict['scan_id']
	scan_id=str(scan_id)
	scanID, dateID = scan_id.split('-')
	url = "https://www.virustotal.com/vtapi/v2/url/report"
	parameters = {"resource": scanID, "apikey": "95c948ffe8c50d27b0087b71c04c1b0ccf074007fe7fa0bc48bf4094063d7088"}
	data = urllib.urlencode(parameters)
	req = urllib2.Request(url, data)
	response = urllib2.urlopen(req)
	json = response.read()
	response_dict = simplejson.loads(json)
	positives = response_dict['positives']
	total = response_dict['total']
	rating = float(positives)/total
	rating = rating*20
	print "Danger rating of " + str(testIP) + " is: " + str(rating) + "\n"
	if rating < 1:
		text_file = open(os.path.join(subdirectory, "whitelist.db"), 'a')
		text_file.write(str(testIP))
		text_file.write("\n")
		text_file.close()
	elif rating < 5:
		text_file = open(os.path.join(subdirectory, "greylist.db"), 'a')
		text_file.write(str(testIP))
		text_file.write("\n")
		text_file.close()
	else:
		text_file = open(os.path.join(subdirectory, "blacklist.db"), 'a')
		text_file.write(str(testIP))
		text_file.write("\n")
	#ACAAAA	text_file.close()

def mainUI():
	global main_win, border_in, t, border_out, t1, border_misc, t2, border_buttons, border_buttons1, border_buttons2, countinPackets, countoutPackets, inpCount, outpCount, aboutbutton, quitButton, viewip, parseButton, screen_height, screen_width,pauseButton,Omenu
	main_win = Tk()
	mwTitle="The Heuristic IDPS: Now listening on Interface "
	mwTitle=mwTitle+str(interface)
	main_win.title(mwTitle)
	main_win.resizable(1, 1)
	#main_win.overrideredirect(True)
	main_win.withdraw()
	
	screen_width = main_win.winfo_screenwidth()
	screen_height = main_win.winfo_screenheight()
	
	menu=Menu(main_win)
	main_win.config(menu=menu)
	fileMenu=Menu(menu,tearoff=False,bd=3,relief=RAISED)
	subMenu=Menu(fileMenu,tearoff=False,bd=3,relief=RAISED)
	subMenu.add_command(label="Select Interface",command=lambda:thrSniff.chInterface,activeforeground="green")
	fileMenu.add_cascade(label="Preferences",menu=subMenu,activeforeground="green")
	fileMenu.add_separator()
	fileMenu.add_command(label="Exit",command=lambda:exitClick(main_win),activeforeground="green")
		
	menu.add_cascade(label="File",menu=fileMenu,activeforeground="green",state=NORMAL)
	
	optionMenu=Menu(menu,tearoff=False,bd=3,relief=RAISED)
	Omenu=Menu(optionMenu,tearoff=False,bd=3,relief=RAISED)
	Omenu.add_command(label="ON",command=optionsON,activeforeground="green")
	Omenu.entryconfigure(1,state=NORMAL)
	Omenu.add_command(label="OFF",command=optionsOFF,activeforeground="green")
	Omenu.entryconfigure(2,state=DISABLED)
	menu.add_cascade(label="Options",menu=optionMenu,activeforeground="green",state=NORMAL)
	optionMenu.add_cascade(label="Advanced Options",menu=Omenu,activeforeground="green",state=NORMAL)


	helpMenu=Menu(menu,tearoff=False,bd=3,relief=RAISED)
	menu.add_cascade(label="Help",menu=helpMenu,activeforeground="green")
	helpMenu.add_command(label="About",command=aboutClick,activeforeground="green")
	
	border_in = Frame(main_win)
	t = Text(border_in, width=screen_width/30,height=screen_height/20,bg="black", fg="red")
	t.pack(fill=BOTH, expand=YES, side="left")
	s = Scrollbar(border_in)
	s.pack(side="right", fill="y")
	s.config(command=t.yview)
	t.config(yscrollcommand=s.set)
	border_in.grid(row=0,column=0,columnspan=1 ,sticky=W)
	
	border_out = Frame(main_win)
	t1 = Text(border_out, width=screen_width/30,height=screen_height/20,bg="black", fg="green")
	t1.pack(side="left", fill="both", expand=YES)
	s1 = Scrollbar(border_out)
	s1.pack(side="right", fill="y")
	s1.config(command=t1.yview)
	t1.config(yscrollcommand=s1.set)
	border_out.grid(row=0,column=1,columnspan=1 ,sticky=W)
	
	border_misc = Frame(main_win)
	t2 = Text(border_misc, width=screen_width/20,height=screen_height/20, bg="black", fg="white")
	t2.pack(side="left", fill="both", expand=YES)
	s2 = Scrollbar(border_misc)
	t2.config(yscrollcommand=s2.set)
	s2.pack(side="right", fill="y")
	s2.config(command=t2.yview)
	border_misc.grid(row=0,column=2,columnspan=2, sticky=W)
	
	border_buttons = Frame(main_win)
	border_buttons.grid(row=4,column=0,columnspan=1)
	
	border_buttons1 = Frame(main_win)
	border_buttons1.grid(row=4,column=1,columnspan=1)
	
	border_buttons2 = Frame(main_win)
	border_buttons2.grid(row=4,column=2,columnspan=2)

	inpCount = StringVar()
	countinPackets=Label(border_buttons2,borderwidth=2,height=1,width=60, textvariable=inpCount)
	countinPackets.pack(fill=BOTH, expand=YES, side="top")
	
	outpCount = StringVar()
	countoutPackets=Label(border_buttons2,borderwidth=2,height=1,width=60, textvariable=outpCount)
	countoutPackets.pack(fill=BOTH, expand=YES, side="top")
	
	image1=Image.open(os.path.join(subdirectory1,"quit.png"))
	image1=image1.resize((90,32), Image.BICUBIC)
	photo1=ImageTk.PhotoImage(image1)
	quitButton=Button(border_buttons,image=photo1,width=70,height=30,command=lambda:exitClick(main_win))
	quitButton.image=photo1
	quitButton.pack(side="left",ipadx=20,pady=7)

	
	image=Image.open(os.path.join(subdirectory1,"IP Table.png"))
	image=image.resize((90,32), Image.BICUBIC)
	photo=ImageTk.PhotoImage(image)
	viewip = Button(border_buttons, width=70,height=32,image=photo,command=ipTables)
	viewip.image=photo
	viewip.pack(side="left",ipadx=10,pady=7)
	
	image2 = Image.open(os.path.join(subdirectory1,"Parse.png"))
	image2 = image2.resize((90,32), Image.BICUBIC)
	photo2 = ImageTk.PhotoImage(image2)
	parseButton = Button(border_buttons, image=photo2, width=70, height=32,command=parseClick)
	parseButton.image=photo2
	parseButton.pack(side="left",ipadx=10,pady=7)

def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


class IPSniff:
    def __init__(self, interface_name, on_ip_incoming, on_ip_outgoing):

        self.interface_name = interface_name
        self.on_ip_incoming = on_ip_incoming
        self.on_ip_outgoing = on_ip_outgoing

        # The raw in (listen) socket is a L2 raw socket that listens
        # for all packets going through a specific interface.
        self.ins = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 ** 30)
        self.ins.bind((self.interface_name, ETH_P_ALL))
        mainUI()
        parseUI()

    def __process_ipframe(self, pkt_type, ip_header, payload):

        # Extract the 20 bytes IP header, ignoring the IP options
        fields = struct.unpack("!BBHHHBBHII", ip_header)

        dummy_hdrlen = fields[0] & 0xf
        iplen = fields[2]

        ip_src = payload[12:16]
        ip_dst = payload[16:20]
        ip_frame = payload[0:iplen]

        if pkt_type == socket.PACKET_OUTGOING:
            if self.on_ip_outgoing is not None:
                self.on_ip_outgoing(ip_src, ip_dst, ip_frame)

        else:
            if self.on_ip_incoming is not None:
                self.on_ip_incoming(ip_src, ip_dst, ip_frame)


    def recv(self):
        while True:
			if (pSniff==0):
				pkt, sa_ll = self.ins.recvfrom(MTU)
				if type == socket.PACKET_OUTGOING and self.on_ip_outgoing is None:
					continue
				elif self.on_ip_outgoing is None:
					continue
				if len(pkt) <= 0:
					break
				eth_header = struct.unpack("!6s6sH", pkt[0:14])
				dummy_eth_protocol = socket.ntohs(eth_header[2])
				if eth_header[2] != 0x800:
					continue
				ip_header = pkt[14:34]
				payload = pkt[14:]
				self.__process_ipframe(sa_ll[2], ip_header, payload)
				time.sleep(0.1)

class sniffThread(Thread):
    def __init__(self,iface):
		self.interface=iface
		super(sniffThread, self).__init__()
		self.stoprequest = Event()

    def run(self):
        while not self.stoprequest.isSet():
            try:
				ip_sniff.interface=self.interface
				ip_sniff.recv()
            except Queue.Empty:
                continue
    
    def chInterface(self):
		global interface, pSniff
		selectInterface()
		pSniff = 1
		ifs = all_interfaces()
		chmsg = "Enter Interface you want to sniff on:\n"
		chtitle = "Interface selection"
		chchoices = ["", "", "", "", "", "", ""]
		chcount = 0
		
		for i in ifs:
		    #   print "%12s   %s" % (i[0], format_ip(i[1]))
		    chmsg += str(i[0])
		    chchoices[chcount] = str(i[0])
		    #	Listbox.insert(listbox, str(i[0]))
		    chcount += 1
		    chmsg += "    "
		    chmsg += str(format_ip(i[1]))
		    chmsg += "\n"
		
		interface = easygui.choicebox(chmsg, chtitle, chchoices)
		self.interface=interface
		ip_sniff.interface=interface

    def stahp(self, timeout=None):
		global pSniff
		pSniff = 1


class parseThread(Thread):
    def __init__(self, tip):
		self.testip = tip
		super(parseThread, self).__init__()
		self.stoprequest = Event()

    def run(self):
		try:
			callParse(self.testip)
		except Exception:
			sys.exit()

    def stahp(self, timeout=None):
		global pParse
		pParse = 1

# Example code to use IPSniff
def test_incoming_callback(src, dst, border_in):
    global inc_txt_str, inc_packet, inc_packet_size
    #print("Incoming: Source=%s, Dest=%s, Len = %d \nFrame data: %s\n\n" %(socket.inet_ntoa(src), socket.inet_ntoa(dst), len(border_in), border_in))
    main_win.deiconify()
    t.configure(state=NORMAL)
    inc_txt_str += "Incoming from "
    inc_txt_str += str(socket.inet_ntoa(src))
    #inc_txt_str += ", Dest="
    #inc_txt_str += str(socket.inet_ntoa(dst))
    inc_txt_str += ", Len = "
    inc_txt_str += str(len(border_in))
    inc_txt_str += "\n"
    inc_packet = inc_packet + 1
    inc_packet_size = inc_packet_size + len(border_in)
    inc_packet_string = "Incoming packets: " + str(inc_packet) + " Total downloaded: " + str(float("{0:.2f}".format(inc_packet_size/1024))) + "kB"
    inpCount.set(str(inc_packet_string))
    #inc_txt_str += str(border_in)
    main_win.update_idletasks()
    #print inc_txt_str
    t.insert(END, inc_txt_str)
    t.see(END)
    t.update_idletasks()
    testip = socket.inet_ntoa(src)
    writeToParse(testip)
    t.configure(state=DISABLED)

def writeToParse(testip):
	global thrParse
	#thrParse = Thread(target=callParse, args=(testip,))
	thrParse = parseThread(testip)
	thrParse.start()

def callParse(tstip):
	ip_local = get_ip_address(interface)
	loctet = ip_local.rfind('.')
	subnet = ip_local[0:loctet]
	cloctet = tstip.rfind('.')
	csubnet = tstip[0:cloctet]
	with open(os.path.join(subdirectory, "parseip.db"), 'a') as text_file:
		t2.configure(state=NORMAL)
		if not str(csubnet) == str(subnet):
			#text_file.write(str(tstip))
			#text_file.write("\n")
			t2.insert(END, tstip)
			t2.insert(END, ": ")
			try:
				sitename=socket.gethostbyaddr(str(tstip))
				sitename=sitename[0]
				sitename=str(sitename)
				if any (x in sitename for x in wl):
					with open(os.path.join(subdirectory, "whitelist.db"), 'r') as wl_IPs:
						try:
							ipList=wl_IPs.read()
							ipList.index(str(tstip)) > -1
						except:
							with open(os.path.join(subdirectory, "whitelist.db"), 'a') as wlList:
								wlList.write(str(tstip))
								wlList.write("\n")
								addtoWL = str(tstip) + "\t" + sitename + "\n"
								whiteltext.configure(state=NORMAL)
								whiteltext.insert(END, addtoWL)
								whiteltext.see(END)
								whiteltext.update_idletasks()
								whiteltext.configure(state=DISABLED)
				elif any (x in sitename for x in bl):
					with open(os.path.join(subdirectory, "blacklist.db"), 'r') as bl_IPs:
						try:
							ipList=bl_IPs.read()
							ipList.index(str(tstip)) > -1
						except:
							with open(os.path.join(subdirectory, "blacklist.db"), 'a') as blList:
								blList.write(str(tstip))
								blList.write("\n")
								addtoBL = str(tstip) + "\t" + sitename + "\n"
								blackltext.configure(state=NORMAL)
								blackltext.insert(END, addtoBL)
								blackltext.see(END)
								blackltext.update_idletasks()
								blackltext.configure(state=DISABLED)
				else:
					with open(os.path.join(subdirectory, "greylist.db"), 'r') as gl_IPs:
						try:
							ipList=gl_IPs.read()
							ipList.index(str(tstip)) > -1
						except:
							with open(os.path.join(subdirectory, "greylist.db"), 'a') as glList:
								glList.write(str(tstip))
								glList.write("\n")
								addtoGL = str(tstip) + "\t" + sitename + "\n"
								greyltext.configure(state=NORMAL)
								greyltext.insert(END, addtoGL)
								greyltext.see(END)
								greyltext.update_idletasks()
								greyltext.configure(state=DISABLED)
			except socket.herror:
				with open(os.path.join(subdirectory, "parseip.db"), 'r') as check_file:
					ipList=check_file.read()
					ipList=str(ipList)
					try:
						ipList.index(str(tstip)) > -1
						sitename="Unknown, already added to parsing list"
					except:
						sitename="Unknown, added to parsing list"
						text_file.write(str(tstip))
						text_file.write("\n")
						tpi.configure(state=NORMAL)
						tpi.insert(END, str(tstip))
						tpi.insert(END, "\t\t")
						tpi.see(END)
						tpi.update_idletasks()
						tpi.configure(state=DISABLED)
			t2.configure(state=NORMAL)
			t2.insert(END, sitename)
			t2.insert(END, "\n")
			t2.see(END)
			t2.update_idletasks()
			t2.configure(state=DISABLED)


def test_outgoing_callback(src, dst, border_in):
    global out_txt_str, out_packet, out_packet_size
    t1.configure(state=NORMAL)
    main_win.deiconify()
    #print("Outgoing: Source=%s, Dest=%s, Len = %d \nFrame data: %s\n\n" %(socket.inet_ntoa(src), socket.inet_ntoa(dst), len(border_in), border_in))
    out_txt_str += "Outgoing to "
    #out_txt_str += str(socket.inet_ntoa(src))
    #out_txt_str += ", Dest="
    out_txt_str += str(socket.inet_ntoa(dst))
    out_txt_str += ", Len = "
    out_txt_str += str(len(border_in))
    out_txt_str += "\n"
    out_packet = out_packet + 1
    out_packet_size = out_packet_size + len(border_in)
    out_packet_string = "Outgoing packets: " + str(out_packet) + " Total uploaded: " + str(float("{0:.2f}".format(out_packet_size/1024))) + "kB"
    outpCount.set(str(out_packet_string))
    #inc_txt_str += str(border_in)
    #frame_out.update_idletasks()
    #print inc_txt_str
    t1.insert(END, out_txt_str)
    t1.see(END)
    t1.update_idletasks()
    testip = socket.inet_ntoa(dst)
    writeToParse(testip)
    t1.configure(state=DISABLED)

def format_ip(addr):
    return str(ord(addr[0])) + '.' + \
           str(ord(addr[1])) + '.' + \
           str(ord(addr[2])) + '.' + \
           str(ord(addr[3]))


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def selectInterface():
	global interface, ip_sniff, thrSniff, pSniff
	ifs = netifaces.interfaces()
	chmsg = "Enter Interface you want to sniff on:\n"
	chtitle = "Interface selection"
	chchoices = ["", "", "", "", "", "", ""]
	chcount = 0
	
	for i in ifs:
		#   print "%12s   %s" % (i[0], format_ip(i[1]))
		chmsg += str(i)
		chchoices[chcount] = str(i)
		#	Listbox.insert(listbox, str(i[0]))
		chcount += 1
		chmsg += "    "
		addrs = netifaces.ifaddresses(str(i))
		try:
			ipaddrs = addrs[netifaces.AF_INET]
			#chmsg += str(format_ip(ipaddrs))
			chmsg += "     "
			chmsg += str(ipaddrs[0]['addr'])
			chmsg += "\n"
		except:
			chmsg += "     "
			chmsg += "Interface Not Up\n"
	interface = easygui.choicebox(chmsg, chtitle, chchoices)
	ip_sniff = IPSniff(interface, test_incoming_callback, test_outgoing_callback)
	#thrSniff = Thread(target=ip_sniff.recv, args=())
	thrSniff = sniffThread(interface)
	thrSniff.start()
	pSniff = 0

selectInterface()

mainloop()
