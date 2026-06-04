import scapy.all as sc 
import optparse as op
import os 
import requests
import json
import ipaddress

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
    prase.add_option("-c","--Compare",dest="COMPARE",help="Check if new devices have been connected or left", default=False,action="store_true")
    prase.add_option("-s","--Spoof",dest="SPOOF",help="Run ARP spoof detection", default=False, action="store_true")
    (options,arguments) = prase.parse_args()

    if not options.IP_ADDRESS:
       detected = get_default_network()
       print(f"[*] No target specified. Auto-detected network: {detected}")
       options.IP_ADDRESS = detected

    return options.IP_ADDRESS, options.FILENAME, options.COMPARE, options.SPOOF
    



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

#fucntion to store the TOOL output in a user specified file
def store_output(data,oui_Dictionary,filename):

    result = []
    for i in data:
        vendor = call_OUI(i["mac"],oui_Dictionary)
        mac = i["mac"]
        ip = i["ip"]

        result.append({"IP":ip, "MAC":mac, "VENDOR":vendor})

    with open(filename,"w")as f:
        json.dump(result,f,indent=3)
        
    print("Data Stored!")  

#--------------------------------------------------------------------
# New Device Detection 
# ------------------------------------------------------------------

baseline_file = "baseline.json"

#function to store the current scan in the baseline file

def save_baseline(data,OUI_Database):
    result = []
    for i in data:
        vendor = call_OUI(i["mac"],OUI_Database)
        result.append({"IP":i["ip"], "MAC":i["mac"], "VENDOR":vendor})
    with open(baseline_file,"w")as f:
        json.dump(result,f,indent=3)
    
    print("Baseline saved")

#function to load/return the baseline file 
def load_baseline():
    with open(baseline_file,"r")as f:
        return json.load(f)
    
#function that compares the current mac address to the baseline mac address
def detect_changes(data,OUI_Database):
    if not os.path.exists(baseline_file):
        print("No baseline file exists!")
        save_baseline(data,OUI_Database)
        return
    
    baseline = load_baseline()

    baseline_mac = {d["MAC"]:d for d in baseline}
    current_mac = {d["mac"]:d for d in data} 

    #actual comparision

    new_devices = [mac for mac in current_mac if mac not in baseline_mac]
    gone_devices = [mac for mac in baseline_mac if mac not in current_mac]

    if not new_devices and not gone_devices:
        return "No changes occured"
    
    if new_devices:
        print("New device detected.")
        for mac in new_devices:
            ip = current_mac[mac]["ip"]
            vendor = call_OUI(mac,OUI_Database)
            print(f"IP: {ip}  MAC: {mac} VENDOR: {vendor}")

    if gone_devices:
        print("Devices that left the network")
        for mac in gone_devices:
            ip = baseline_mac[mac]["IP"]
            vendor = baseline_mac[mac]["VENDOR"]
            print(f"IP: {ip} MAC: {mac} VENDOR: {vendor}")

#------------------------------------
# Retriving the default gateway ip if the user did not specify a ip address 
#------------------------------------

def get_default_network():
   Default_gateway = sc.conf.route.route("0.0.0.0")[2] 

   result = ipaddress.IPv4Network(Default_gateway +"/24" ,strict=False)

   return str(result)

#------------------------------------------
# Checking if there r any one mac but 2 ip situation (arp Spoofing)
# -----------------------------------------

def detect_arp_spoofing(data,OUI_Database):
    mac_to_ip = {}
    for i in data:
        ip =  i["ip"]
        mac = i["mac"]
        if mac not in mac_to_ip:
            mac_to_ip[mac] = []
        
        mac_to_ip[mac].append(ip)
        
    spoofing_detected =False
    for mac , ips in mac_to_ip.items():
        if len(ips) > 1:
            spoofing_detected = True
            print("[!!!] DUPLICATE MAC DETECTED - possible ARP spoof!")
            print(f"MAC {mac}      is claimed by multiple IPS  {', ' .join(ips)}")
            vendor = call_OUI(mac,OUI_Database)
            print(f"Vendor :{vendor}")

#------------------------------
# checking if the default gateway mac has be changed by comeparing the current scan with the baseline scan
# -----------------------------

    gateway_ip = sc.conf.route.route("0.0.0.0")[2]
    current_gateway_mac = None

    for i in data:
        if i["ip"] == gateway_ip:
            current_gateway_mac = i["mac"]
            break
    
    if current_gateway_mac == None:
        print("[*] Gateway not found in the current scan")    
        exit(1)
    elif os.path.exists("baseline.json"):
        with open("baseline.json","r") as f:
            result = json.load(f)
        baseline_gateway_mac = None
        for i in result:
            if i["IP"] == gateway_ip:
                baseline_gateway_mac = i["MAC"]
                break

            # ensuring that we have the gateway mac from the router first as we dont want to comepare the current mac with a None
        if baseline_gateway_mac and current_gateway_mac != baseline_gateway_mac:
                spoofing_detected = True
                print(f"\n[!!!] GATEWAY MAC CHANGED — possible ARP spoof!")
                print(f"      Gateway IP  : {gateway_ip}")
                print(f"      Baseline MAC: {baseline_gateway_mac}")
                print(f"      Current MAC : {current_gateway_mac}")
        else:
                print("[+] Gateway MAC unchanged.")
    else:
        print(f"[*] No baseline to compare gateway MAC. Current: {current_gateway_mac}")

    if not spoofing_detected:
        print("[+] No ARP spoofing detected.")
        
 

IP,filename,Compare,spoof = arguments()
Download_OUI()
OUI_Dictionary = load_OUI()
data = scan(IP)

print_details(data, OUI_Dictionary)

if Compare:
    detect_changes(data, OUI_Dictionary)
if spoof:
    detect_arp_spoofing(data, OUI_Dictionary)
if filename:
    store_output(data, OUI_Dictionary, filename)



