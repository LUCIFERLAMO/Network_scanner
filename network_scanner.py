import scapy.all as sc 

#basic function to do an ARP scan of an given ip 
def scan(ip):
    ethernet_frame = sc.Ether(dst="ff:ff:ff:ff:ff:ff") 
    arp_scanner = sc.ARP(pdst=ip) # creating an object for the class .arp() we r creating an arp packet here as it deals with layer 3.
    arp_scan_packet = ethernet_frame / arp_scanner # created a packet which goes in the network broadcast address and send the arp request
    answered = sc.srp(arp_scan_packet, timeout = 1,verbose=False)[0] # saying we dont need more info
    #print(answered.summary())

    print("IP addesss\t\t\tMAC ADDRESS")
    for i in answered:
        print(f"{i[1].psrc}                   {i[1].src}")
       



    

scan("192.168.1.1/24")



