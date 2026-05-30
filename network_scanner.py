import scapy.all as sc 
import optparse as op
import os 

def arguments():

    #if user is not root then stop the user
    if os.geteuid() != 0:
        print("-" * 50)
        print("[-] ROOT REQUIRED")
        print("-" * 50)
        exit(1)

    prase = op.OptionParser()

    prase.add_option("-i","--ip",dest="IP_ADDRESS",help="Takes an ip address")

    (options,arguments) = prase.parse_args()

    if not options.IP_ADDRESS:
        prase.error("Ip address is required. use --help")
    
    
    
    return options.IP_ADDRESS
    



#basic function to do an ARP scan of an given ip 
def scan(ip):
    #create the layer 2 level
    ethernet  = sc.Ether("ff:ff:ff:ff:ff:ff")
    #create the level 3 packet
    Ip_address = sc.ARP(ptsd=ip)
    #combine the layer 2 and 3 and make a packet
    packet = ethernet/Ip_address
    answered = sc.srp(packet,timeout = 1,verbose=False)[0]

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



