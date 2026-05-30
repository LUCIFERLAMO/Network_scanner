import scapy.all as sc 
import optparse as op

def arguments():
    prase = op.OptionParser()

    prase.add_option("-i","--ip",dest="IP_ADDRESS",help="Takes an ip address")

    (options,arguments) = prase.parse_args()

    if not options.IP_ADDRESS:
        prase.error("Ip address is required. use --help")
    else:
        return options.IP_ADDRESS
    



#basic function to do an ARP scan of an given ip 
def scan(ip):
    ethernet_frame = sc.Ether(dst="ff:ff:ff:ff:ff:ff") 
    arp_scanner = sc.ARP(pdst=ip) # creating an object for the class .arp() we r creating an arp packet here as it deals with layer 3.
    arp_scan_packet = ethernet_frame / arp_scanner # created a packet which goes in the network broadcast address and send the arp request
    answered = sc.srp(arp_scan_packet, timeout = 1,verbose=False)[0] # saying we dont need more info
    #print(answered.summary())

    info = []
    
    for i in answered:
        dict = {"ip":i[1].psrc , "mac":i[1].src }
        info.append(dict)
        
    return info    

def printt(data):
    print("IP addesss\t\t\tMAC ADDRESS")
    for i in data:
        print(i["ip"] + "\t\t\t" + i["mac"])


IP = arguments()
data = scan(IP)
printt(data)



