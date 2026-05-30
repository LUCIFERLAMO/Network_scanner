import scapy.all as sc 

#basic function to do an ARP scan of an given ip 
def scan(ip):
    arp_scanner = sc.ARP(pdst=ip) # creating an object for the class .arp() we r creating an arp packet here as it deals with layer 3.
    ethernet_frame = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_scan_packet = ethernet_frame / arp_scanner # created a packet which goes in the network broadcast address and send the arp request
    arp_scan_packet.show()

    

scan("192.168.1.1")



