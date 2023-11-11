import subprocess
import platform
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import whois
import nmap
import scapy.all as scapy
from colorama import *
from termcolor import colored
import os

def clear_screen():
    if platform.system().lower() == 'windows':
        os.system('cls')
    else:
        os.system('clear')

def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(colored(f"Error executing command: {e}", 'yellow'))

def add_protocol(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        return 'https://' + url
    return url

def crawl_website():
    url = input(colored("Enter the website URL: ", 'yellow'))
    url = add_protocol(url)
    print(colored(f"Crawling website: {url}", 'yellow'))
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')
        for link in links:
            print(colored(link.get('href'), 'yellow'))
    else:
        print(colored(f"Failed to crawl {url}. Status code: {response.status_code}", 'yellow'))

def dir_bruteforce():
    url = input(colored("Enter the website URL: ", 'yellow'))
    url = add_protocol(url)
    print(colored(f"Bruteforcing directories on: {url}", 'yellow'))
    run_command(f"dirb {url}")

def dns_lookup():
    hostname = input(colored("Enter the hostname: ", 'yellow'))
    print(colored(f"Performing DNS lookup for: {hostname}", 'yellow'))
    run_command(f"nslookup {hostname}")

def dns_zone_transfer():
    domain = input(colored("Enter the domain for DNS zone transfer: ", 'yellow'))
    print(colored(f"Performing DNS zone transfer for: {domain}", 'yellow'))
    if platform.system().lower() == 'windows':
        run_command(f"nslookup -type=ns {domain}")
    else:
        run_command(f"dig axfr {domain}")

def http_headers():
    url = input(colored("Enter the website URL: ", 'yellow'))
    url = add_protocol(url)
    print(colored(f"Fetching HTTP headers for: {url}", 'yellow'))
    try:
        response = requests.head(url)
        headers = response.headers
        for key, value in headers.items():
            print(colored(f"{key}: {value}", 'yellow'))
    except requests.RequestException as e:
        print(colored(f"Error: {e}", 'yellow'))

def ip_geolocation():
    hostname = input(colored("Enter the hostname or IP address: ", 'yellow'))
    print(colored(f"Performing IP geolocation for: {hostname}", 'yellow'))
    try:
        ip_address = socket.gethostbyname(hostname)
        response = requests.get(f"https://freegeoip.app/json/{ip_address}")
        data = response.json()
        print(colored(f"IP: {ip_address}", 'yellow'))
        print(colored(f"Country: {data['country_name']}", 'yellow'))
        print(colored(f"Region: {data['region_name']}", 'yellow'))
        print(colored(f"City: {data['city']}", 'yellow'))
        print(colored(f"Latitude: {data['latitude']}", 'yellow'))
        print(colored(f"Longitude: {data['longitude']}", 'yellow'))
    except socket.error as e:
        print(colored(f"Error: {e}", 'yellow'))

def port_scan():
    hostname = input(colored("Enter the hostname or IP address: ", 'yellow'))
    print(colored(f"Performing port scan for: {hostname}", 'yellow'))
    try:
        nm = nmap.PortScanner()
        nm.scan(hostname, arguments='-p 1-1000')  # Adjust port range as needed
        for host in nm.all_hosts():
            print(colored(f"Host: {host}", 'yellow'))
            for proto in nm[host].all_protocols():
                print(colored(f"Protocol: {proto}", 'yellow'))
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    print(colored(f"Port: {port}, State: {state}", 'yellow'))
    except nmap.NmapError as e:
        print(colored(f"Error: {e}", 'yellow'))

def reverse_dns():
    hostname = input(colored("Enter the IP address: ", 'yellow'))
    print(colored(f"Performing reverse DNS lookup for: {hostname}", 'yellow'))
    try:
        hostnames, _, _ = socket.gethostbyaddr(hostname)
        print(colored(f"IP Address: {hostname}", 'yellow'))
        print(colored(f"Hostnames: {', '.join(hostnames)}", 'yellow'))
    except socket.error as e:
        print(colored(f"Error: {e}", 'yellow'))

def robots_txt():
    url = input(colored("Enter the website URL: ", 'yellow'))
    url = add_protocol(url)
    print(colored(f"Fetching robots.txt for: {url}", 'yellow'))
    try:
        robots_url = f"{url}/robots.txt"
        response = requests.get(robots_url)
        if response.status_code == 200:
            print(colored(response.text, 'yellow'))
        else:
            print(colored(f"Failed to fetch {robots_url}. Status code: {response.status_code}", 'yellow'))
    except requests.RequestException as e:
        print(colored(f"Error: {e}", 'yellow'))

def ssl_info():
    hostname = input(colored("Enter the hostname: ", 'yellow'))
    print(colored(f"Fetching SSL information for: {hostname}", 'yellow'))
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(colored(f"Issuer: {cert['issuer'][0][0]}", 'yellow'))
                print(colored(f"Subject: {cert['subject'][0][0]}", 'yellow'))
                print(colored(f"Valid From: {cert['notBefore']}", 'yellow'))
                print(colored(f"Valid Until: {cert['notAfter']}", 'yellow'))
    except (socket.error, ssl.SSLError) as e:
        print(colored(f"Error: {e}", 'yellow'))

def subdomain_enum():
    domain = input(colored("Enter the domain for subdomain enumeration: ", 'yellow'))
    print(colored(f"Performing subdomain enumeration for: {domain}", 'yellow'))
    run_command(f"sublist3r -d {domain}")

def traceroute():
    hostname = input(colored("Enter the hostname or IP address: ", 'yellow'))
    print(colored(f"Tracerouting to: {hostname}", 'yellow'))
    try:
        result, _, _ = scapy.traceroute(hostname, maxttl=20)
        for entry in result:
            print(colored(entry, 'yellow'))
    except socket.error as e:
        print(colored(f"Error: {e}", 'yellow'))

def whois_lookup():
    hostname = input(colored("Enter the hostname: ", 'yellow'))
    print(colored(f"Performing WHOIS lookup for: {hostname}", 'yellow'))
    try:
        whois_info = whois.whois(hostname)
        print(colored(whois_info, 'yellow'))
    except whois.parser.PywhoisError as e:
        print(colored(f"Error: {e}", 'yellow'))

while True:
    init()
    clear_screen()
    print(colored("""
      _.--._
      \ ** /
       (<>)                     CYBERSAINT - Cyber Security & Advanced Intrusion Network Toolkit
.      )  (      .
)\_.._/ /\ \_.._/(
(*_<>_      _<>_*)              [ 1. Crawl Website                  ]                     [ 2.Directory Bruteforce        ]
)/ '' \ \/ / '' \(              [ 3. DNS Lookup                     ]                     [ 4. DNS Zone Transfer          ]
'      )  (      '              [ 5. Fetch HTTP Headers             ]                     [ 6. Perform IP Geolocation     ]
       (  )                     [ 7. Perform Port Scan              ]                     [ 8. Perform Reverse DNS Lookup ]
       )  (                     [ 9. Fetch robots.txt               ]                     [ 10. Fetch SSL Information     ]
       (<>)                     [ 11. Perform Subdomain Enumeration ]                     [ 12. Perform Traceroute        ]       
      / ** \                    [ 13. Perform WHOIS Lookup          ]                     [ 14. Exit                      ]
     /.-..-.\ 

        """, 'yellow'))
    choice = input(colored("                                                Enter the number of your choice:", 'yellow'))

    if choice == '1':
        crawl_website()
    elif choice == '2':
        dir_bruteforce()
    elif choice == '3':
        dns_lookup()
    elif choice == '4':
        dns_zone_transfer()
    elif choice == '5':
        http_headers()
    elif choice == '6':
        ip_geolocation()
    elif choice == '7':
        port_scan()
    elif choice == '8':
        reverse_dns()
    elif choice == '9':
        robots_txt()
    elif choice == '10':
        ssl_info()
    elif choice == '11':
        subdomain_enum()
    elif choice == '12':
        traceroute()
    elif choice == '13':
        whois_lookup()
    elif choice == '14':
        print(colored("Exiting the program. Goodbye!", 'yellow'))
        break
    else:
        print(colored("Invalid choice. Please enter a valid number.", 'yellow'))

    input(colored("Press Enter to continue...", 'yellow'))
