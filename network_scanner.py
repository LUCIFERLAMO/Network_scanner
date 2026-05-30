import scapy.all as sc 

#basic function to do an ARP scan of an given ip 
def scan(ip):
    arp_scanner = sc.ARP(pdst=ip) # creating an object for the class .arp()
    sc.ls(arp_scanner) # will list all the parameters of the class .arp()
    print(arp_scanner.summary())

    

scan("192.168.1.1")



