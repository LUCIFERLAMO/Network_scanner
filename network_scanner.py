import scapy.all as sc 
import optparse as op
import os 
import requests
import json

def arguments():

    #if user is not root then stop the user
    if os.geteuid() != 0:
        print("-" * 50)
        print("[-] ROOT REQUIRED")
        print("-" * 50)
        exit(1)

    prase = op.OptionParser()

    prase.add_option("-i","--ip",dest="IP_ADDRESS",help="Takes an ip address")
    prase.add_option("-o","--output",dest="FILENAME", help="Saving the output in a file (JSON format)", default=False) 

    (options,arguments) = prase.parse_args()

    if not options.IP_ADDRESS:
        prase.error("Ip address is required. use --help")
    if options.FILENAME:
        return options.IP_ADDRESS,options.FILENAME  
    
     
    return options.IP_ADDRESS, None
    



#basic function to do an ARP scan of an given ip 
def scan(ip):
    #create the layer 2 level
    ethernet  = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
    #create the level 3 packet
    Ip_address = sc.ARP(pdst=ip)
    #combine the layer 2 and 3 and make a packet
    packet = ethernet/Ip_address
    answered = sc.srp(packet,timeout = 1,verbose=False)[0]

    info = []
    
    for i in answered:
        dict = {"ip":i[1].psrc , "mac":i[1].src }
        info.append(dict)
        
    return info    


def Download_OUI():

    if not os.path.exists("OUI_Database"):
       # go to the website and get the OCI data
       header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/137.0"}
       target_url = "https://standards-oui.ieee.org/oui/oui.txt"

       information = requests.get(
            target_url,
            headers=header,
            timeout=10 )
    
       with open("OUI_Database","w",errors="ignore")as f:
             f.write(information.text) # the .text gives the entier html code or the context of the requeted document


#creating a dictionary of mac prefix and vendor names
def load_OUI():
    OUI = {}

    with open("OUI_Database","r")as f:
        for line in f:
            if "(hex)" not in line:  # as the line contaiines some unwanted things like OUI/MA--- which is not required
                continue
            
            result = line.split("(hex)")
            Not_changed_OCI_mac = result[0].strip()
            OUI_MAC = Not_changed_OCI_mac.replace("-",":")
            names = result[1].strip()
            OUI[OUI_MAC] = names

    return OUI # RETURNS the mac and the names in a dictionary format


#Retriving/checking if the MAC prefix [first 3 bytes] exist in the OUI_Dictionary or not
def call_OUI(mac_address,OUI_Dictionary):
    prefix = mac_address.upper()[0:8]
    return OUI_Dictionary.get(prefix,"Nothing")
    
    
#data = list of ip and mac
def print_details(data,oui_Dictionary):
    print("-" * 70)
    print("IP addesss\t\t\tMAC ADDRESS\t\tVENDOR")
    print("-" * 70)
    for i in data:
        vendor = call_OUI(i["mac"],oui_Dictionary)
        print(i["ip"] + "\t\t\t" + i["mac"]+"\t" +vendor)


def store_output(data,oui_Dictionary,filename):


    for i in data:
        vendor = call_OUI(i["mac"],oui_Dictionary)
        mac = i["mac"]
        ip = i["ip"]

        store_value = {"IP":ip, "MAC":mac, "VENDOR":vendor}

        with open(filename,"a")as f:
            json.dump(store_value,f,indent=3)
        
    print("Data Stored!")    

IP,filename = arguments()
Download_OUI()
OUI_Dictionary = load_OUI()
data = scan(IP)

if filename:
      store_output(data,OUI_Dictionary,filename)
else:      
      print_details(data,OUI_Dictionary)



