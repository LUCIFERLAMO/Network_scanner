import scapy.all as sc 
import optparse as op
import os 
import requests
import json
import ipaddress
from rich.console import Console
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

#------------------------------------
# Retriving the default gateway ip if the user did not specify a ip address 
#------------------------------------

def get_default_network():
   Default_gateway = sc.conf.route.route("0.0.0.0")[2] 
   result = ipaddress.IPv4Network(Default_gateway +"/24" ,strict=False)
   return str(result)


def arguments():

    #if user is not root then stop the user
    if os.geteuid() != 0:
        console.print("[bold red]" + "-" * 50 + "[/bold red]")
        console.print("[bold red][-] ROOT REQUIRED[/bold red]")
        console.print("[bold red]" + "-" * 50 + "[/bold red]")
        exit(1)

    prase = op.OptionParser()

    prase.add_option("-i","--ip",dest="IP_ADDRESS",help="Takes an ip address")
    prase.add_option("-o","--output",dest="FILENAME", help="Saving the output in a file (JSON format)", default=None)
    prase.add_option("-c","--Compare",dest="COMPARE",help="Check if new devices have been connected or left", default=False,action="store_true")
    prase.add_option("-s","--Spoof",dest="SPOOF",help="Run ARP spoof detection", default=False, action="store_true")
    (options,arguments) = prase.parse_args()

    if not options.IP_ADDRESS:
       detected = get_default_network()
       console.print(f"[cyan][*] No target specified. Auto-detected network: {detected}[/cyan]")
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
       console.print("[cyan][*] Downloading OUI database...[/cyan]")
       header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/137.0"}
       target_url = "https://standards-oui.ieee.org/oui/oui.txt"

       information = requests.get(
            target_url,
            headers=header,
            timeout=10)
    
       with open("OUI_Database","w",errors="ignore")as f:
             f.write(information.text) # the .text gives the entier html code or the context of the requeted document
       console.print("[green][+] OUI database ready.[/green]")


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
    return OUI_Dictionary.get(prefix,"Unknown")


#data = list of ip and mac
def print_details(data,oui_Dictionary):
    table = Table(title="Network Scan Results", box=box.ROUNDED, header_style="bold cyan")
    table.add_column("IP ADDRESS", style="green")
    table.add_column("MAC ADDRESS", style="yellow")
    table.add_column("VENDOR", style="white")
    for i in data:
        vendor = call_OUI(i["mac"],oui_Dictionary)
        table.add_row(i["ip"], i["mac"], vendor)
    console.print(table)
    console.print(f"[bold green][+] {len(data)} device(s) found[/bold green]")


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
        
    console.print(f"[green][+] Data saved to {filename}[/green]")


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
    console.print("[green][+] Baseline saved.[/green]")


#function to load/return the baseline file 
def load_baseline():
    with open(baseline_file,"r")as f:
        return json.load(f)

    
#function that compares the current mac address to the baseline mac address
def detect_changes(data,OUI_Database):
    if not os.path.exists(baseline_file):
        console.print("[yellow][!] No baseline found. Saving current scan as baseline.[/yellow]")
        save_baseline(data,OUI_Database)
        return
    
    baseline = load_baseline()

    baseline_mac = {d["MAC"]:d for d in baseline}
    current_mac = {d["mac"]:d for d in data} 

    #actual comparision
    new_devices = [mac for mac in current_mac if mac not in baseline_mac]
    gone_devices = [mac for mac in baseline_mac if mac not in current_mac]

    if not new_devices and not gone_devices:
        console.print("[green][+] No changes detected.[/green]")
        return
    
    if new_devices:
        console.print("\n[bold red][!] NEW DEVICES DETECTED:[/bold red]")
        for mac in new_devices:
            ip = current_mac[mac]["ip"]
            vendor = call_OUI(mac,OUI_Database)
            console.print(f"  [red]IP: {ip}  MAC: {mac}  VENDOR: {vendor}[/red]")

    if gone_devices:
        console.print("\n[bold yellow][!] DEVICES THAT LEFT THE NETWORK:[/bold yellow]")
        for mac in gone_devices:
            ip = baseline_mac[mac]["IP"]
            vendor = baseline_mac[mac]["VENDOR"]
            console.print(f"  [yellow]IP: {ip}  MAC: {mac}  VENDOR: {vendor}[/yellow]")


#------------------------------------------
# Checking if there r any one mac but 2 ip situation (arp Spoofing)
# -----------------------------------------

def detect_arp_spoofing(data,OUI_Database):
    console.print("\n[cyan][*] Running ARP spoof detection...[/cyan]")
    mac_to_ip = {}
    for i in data:
        ip =  i["ip"]
        mac = i["mac"]
        if mac not in mac_to_ip:
            mac_to_ip[mac] = []
        mac_to_ip[mac].append(ip)
        
    spoofing_detected = False
    for mac, ips in mac_to_ip.items():
        if len(ips) > 1:
            spoofing_detected = True
            console.print("[bold red][!!!] DUPLICATE MAC DETECTED — possible ARP spoof![/bold red]")
            console.print(f"  [red]MAC {mac} is claimed by multiple IPs: {', '.join(ips)}[/red]")
            vendor = call_OUI(mac,OUI_Database)
            console.print(f"  [red]Vendor: {vendor}[/red]")

    #------------------------------
    # checking if the default gateway mac has been changed by comparing the current scan with the baseline scan
    #------------------------------

    gateway_ip = sc.conf.route.route("0.0.0.0")[2]
    current_gateway_mac = None

    for i in data:
        if i["ip"] == gateway_ip:
            current_gateway_mac = i["mac"]
            break
    
    if current_gateway_mac == None:
        console.print("[yellow][!] Gateway not found in the current scan.[/yellow]")
    elif os.path.exists("baseline.json"):
        with open("baseline.json","r") as f:
            result = json.load(f)
        baseline_gateway_mac = None
        for i in result:
            if i["IP"] == gateway_ip:
                baseline_gateway_mac = i["MAC"]
                break

        # ensuring that we have the gateway mac from the router first as we dont want to compare the current mac with a None
        if baseline_gateway_mac and current_gateway_mac != baseline_gateway_mac:
            spoofing_detected = True
            console.print("[bold red][!!!] GATEWAY MAC CHANGED — possible ARP spoof![/bold red]")
            console.print(f"  [red]Gateway IP  : {gateway_ip}[/red]")
            console.print(f"  [red]Baseline MAC: {baseline_gateway_mac}[/red]")
            console.print(f"  [red]Current MAC : {current_gateway_mac}[/red]")
        else:
            console.print("[green][+] Gateway MAC unchanged.[/green]")
    else:
        console.print(f"[cyan][*] No baseline to compare gateway MAC. Current: {current_gateway_mac}[/cyan]")

    if not spoofing_detected:
        console.print("[bold green][+] No ARP spoofing detected.[/bold green]")


IP,filename,Compare,spoof = arguments()
Download_OUI()
OUI_Dictionary = load_OUI()

with Progress(SpinnerColumn(), TextColumn("[cyan]Scanning network...")) as progress:
    progress.add_task("scan")
    data = scan(IP)

print_details(data, OUI_Dictionary)

if Compare:
    detect_changes(data, OUI_Dictionary)
if spoof:
    detect_arp_spoofing(data, OUI_Dictionary)
if filename:
    store_output(data, OUI_Dictionary, filename)