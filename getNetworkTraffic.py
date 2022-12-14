import pyshark
import csv
from datetime import date
import time

ports = ['3478', '3479', '8801', '8802', '8803', '8804', '8805', '8806', '8807', '8808',
         '8809', '8810']
IPlist = []
portDict = {}
zoomDict = {}

with open('zoomIPs.txt', "r") as zoomIPs:
        IPs = zoomIPs.read().splitlines()
        for IP in IPs:
                IPlist.append(IP.rsplit('.', 2)[0])

capture = pyshark.LiveCapture(interface='en0')
capture.sniff(timeout=10)
#print(capture)

class findZoom:
        def sniff(self):
                for packet in capture.sniff_continuously(packet_count=len(capture)):
                        try:
                                if hasattr(packet, 'udp'):
                                        self.source_address = packet.ip.src.rsplit('.', 2)[0]
                                        self.source_port = packet[packet.transport_layer].srcport
                                        portDict.update({self.source_address:self.source_port})
                        except AttributeError:
                                pass
        def detectAttributes(self):
                #print(portDict)
                for ip in IPlist:
                        if ip in portDict.keys():
                                self.zoomIP = ip
                for port in ports:
                        if port in portDict.values():
                                self.zoomPort = port
        def detectZoom(self):
                today = date.today()
                day = today.strftime("%Y%m%d")
                now = time.strftime("%H:%M:%S")
                print(now)
                with open(f'logger_{day}.csv', 'a') as f:
                        logger = csv.writer(f, delimiter=',', quoting=csv.QUOTE_NONE)
                        try:
                                if self.zoomIP in IPlist and self.zoomPort in ports:
                                        print("Zoom active")
                                        logger.writerow([now, "Zoom active"])
                        except AttributeError:
                                print("Zoom not active")
                                logger.writerow([now, "Zoom not active"])

sniffer = findZoom()
sniffer.sniff()
sniffer.detectAttributes()
sniffer.detectZoom()