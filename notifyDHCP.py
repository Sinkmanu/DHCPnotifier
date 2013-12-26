#!/usr/bin/env python
# -*- coding: utf-8 -*-
# notifyDHCP: Launch a notify when a client is handshaking with the server


from scapy.all import sniff,BOOTP,DHCPOptions,DHCP
import struct
import string
import pynotify
import os
import sys
import dbus
import datetime
	

uid = 1000

def notificacion(uid,head,mensaje):
	pid_t = os.fork()
	if pid_t == 0:	
		os.setuid(uid)
		try:
			bus = dbus.bus.BusConnection(os.environ["DBUS_SESSION_BUS_ADDRESS"])
			notify_object = bus.get_object('org.freedesktop.Notifications','/org/freedesktop/Notifications')
			notify_interface = dbus.Interface(notify_object,'org.freedesktop.Notifications')
			noti_id = notify_interface.Notify("DHCPNotifier", 0,"", head,mensaje, '',{},10000)

		except dbus.DBusException, err:
			  print err
		sys.exit(0)
			  
def getNameFromMAC(mac):
	fich = open("./deviceMAC.txt","r")
	cont = 0
	e = 0
	lines = len(fich.readlines())
	fich.seek(0)
	while cont < lines:
            cad = fich.readline()
            if mac == cad.split(",")[3].replace("\n", ''):
                name = cad.split(",")[1]
                fich.close()
                return name
            else:
                cont = cont+1
        fich.close()
        return "Unknown"            

def add2log(dhcp_type,mac,other):
	""" Function to add MAC and dates to the log """
	fich = open('./log_DHCPnotifier',"a")
	fich.write(unicode(datetime.datetime.now())+": DHCP "+ dhcp_type+" from "+ mac + " : " + other+"\n")
	fich.close()

def DHCPtype(num_type):
    if (num_type == 1):
        return "Discover"
    elif (num_type == 2):
        return "Offer"
    elif (num_type == 3):
        return "Request"


    
def printMAC(pkt):
    """ Function what it is executed when has a DHCP Packet """

    mac_bootp =  ':'.join(['%02x' % ord(x) for x in pkt.chaddr[:6]]) 
    mac_ether = pkt.sprintf("%Ether.src%") # Ether.src debe de coincidir con BOOTP.chaddr
    
    dhcp_type = DHCPtype(pkt[DHCP].options[0][1])
    if (mac_ether == mac_bootp):
		   notificacion(uid,"DHCP %s:"%dhcp_type,"%s (%s)"%(getNameFromMAC(mac_bootp),mac_bootp))
		   add2log(dhcp_type,mac_bootp,getNameFromMAC(mac_bootp))
	    
    else:
        if (dhcp_type == "Offer"):
		   notificacion(uid,"SPOOF DHCP %s:"%dhcp_type,"%s - %s"%(mac_bootp,pkt[BOOTP].yiaddr))
		   add2log(dhcp_type,mac_bootp,pkt[BOOTP].yiaddr)
        else:
		   notificacion(uid,"SPOOF DHCP %s:"%dhcp_type,"%s - %s"%(mac_bootp,mac_ether))
		   add2log(dhcp_type,mac_bootp,mac_ether)



def as_daemon():
	pid = os.fork()
	if pid > 0:
		sys.exit(0)
	pid = os.fork()
	if pid > 0:
		sys.exit(0)
	if pid == 0:
		os.chdir("/")
		os.setsid()
		os.umask(0)
		sys.stdout.flush()
		sys.stderr.flush()
		si = file('/dev/null', 'r')
                so = file('/dev/null', 'a+')
                se = file('/dev/null', 'a+', 0)
                os.dup2(si.fileno(), sys.stdin.fileno())
                os.dup2(so.fileno(), sys.stdout.fileno())
                os.dup2(se.fileno(), sys.stderr.fileno())
		pid = str(os.getpid())
		file("/var/run/DHCPNotifier.pid",'w+').write("%s\n" % pid)		
		sniff(filter="port 67 or port 68",prn=printMAC)
	
def help_menu():
	print '''\
Help Menu for DHCPNotifier
Options include:
        --daemon                : Start daemon.
	--help     		: Show help	'''

if __name__ == "__main__":
    if (len(sys.argv) == 1):
	    sniff(filter="port 67 or port 68",prn=printMAC)
    elif  sys.argv[1].startswith('--'):
	    option = sys.argv[1][2:]
	    if (option == 'daemon'):
		    print 'Starting daemon DHCPNotifier'
		    as_daemon()
	    elif (option == 'help'):
		    help_menu()
	    else:
		    help_menu()




