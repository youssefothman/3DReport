import csv
import json
import re
from urllib.request import urlopen
from getSSL_cert_issuer import get_issuer
import os

whois_key = os.getenv("WHOIS_API_KEY")
threatint_key = os.getenv("THREATINT_API_KEY")


def switch(value):
    if value in ["CSC", "GlobalSign", "Entrust", "Sectigo", "DigiCert", "Comodo"]:
        return 90
    elif value == "QuoVadis":
        return 80
    elif value in ["Amazon", "Actalis"]:
        return 50
    elif value == "Symantec":
        return 30
    elif value in ["Network Solutions", "Godaddy", "Let's Encrypt", "Microsoft", "ZeroSSL", "Google Trust Services LLC"]:
        return 10
    elif value in ["Buypass", "IdenTrust", "Qihoo", "Asseco", "Taiwan", "Trustwave", "Terena", "WoSign"]:
        return 0
    else:
        return "N/A"


def format_list(lista):
    result = str(lista)
    result = result.replace(',', '\r\n').replace("'", "").replace('[', '').replace(']', '')
    return result


def fix_case(word):
    final_list = word.split()
    final = ""
    for w in final_list:
        final += w[0].upper()
        final += w[1::].lower()
        final += " "
    return final.strip()


def clean_registrar(name):
    """ Normalize registrar names: remove suffixes, fix capitalization, and standardize known brands """
    
    # List of common suffixes to remove
    suffixes = r"\b(LLC|Inc\.?|Ltd\.?|Corp\.?|S\.A\.?|Pty\.?|Limited|GmbH|UAB|A\.S\.|Co\.,?|B\.V\.|AG|SAS|SL|OÜ|Sp\.? z o\.o\.)\b"

    # Remove known suffixes
    name = re.sub(suffixes, "", name, flags=re.IGNORECASE).strip()

    # Remove unnecessary dots and extra spaces
    name = re.sub(r"\s*\.\s*", " ", name).strip()
    name = re.sub(r"\s+", " ", name)  # Ensure single spaces only

    # Remove a trailing "com" that may be left behind
    if name.lower().endswith(" com"):
        name = name[:-4].strip()

    # Standardized known registrars (correct formatting)
    known_brands = {
        "GoDaddy": "GoDaddy",
        "GoDaddy.com": "GoDaddy",
        "Namecheap": "Namecheap",
        "Dynadot": "Dynadot",
        "Tucows": "Tucows",
        "Tucows Domains": "Tucows",
        "Squarespace": "Squarespace",
        "BigRock": "BigRock",
        "NameSilo": "NameSilo",
        "Spaceship": "Spaceship",
        "Edomains": "Edomains",
        "Hostinger": "Hostinger",
        "Ascio Technologies": "AscioTech",
        "Key-Systems": "Key-Systems",
        "Dotserve": "Dotserve",
        "Hosting Ukraine": "HostingUkraine",
        "Dominet": "Dominet",
        "NICS Telekomunikasyon": "NICSTele",
        "Network Solutions": "NetworkSolutions",
        "Google Domains": "Google Domains",
        "1&1 IONOS": "1&1 IONOS",
        "Alibaba Cloud Computing": "Alibaba",
        "Bluehost": "Bluehost",
        "Porkbun": "Porkbun",
        "Enom": "Enom",
        "FastDomain": "FastDomain",
        "Gandi": "Gandi",
        "OVH": "OVH",
        "Reg.ru": "Reg.ru",
        "Names.co.uk": "Names.co.uk",
        "101domain": "101domain",
        "MarkMonitor": "MarkMonitor",
        "CSC Corporate Domains": "CSC Corporate Domains",
        "NameBright": "NameBright",
        "Netim": "Netim",
        "Amazon Registrar": "Amazon",
        "Cloudflare": "Cloudflare",
        "Epik": "Epik",
        "EuroDNS": "EuroDNS",
        "Gransy": "Gransy",
        "OnlineNIC": "OnlineNIC",
        "Sav.com": "Sav",
        "Dynadot LLC": "Dynadot",
        "Google Trust Services": "GoogleTrust",
        "Alibaba": "Alibaba Cloud",
        "1API": "1API",
        "GMO Internet": "GMO Internet",
        "Rebel.ca": "Rebel.ca",
        "Netregistry": "Netregistry",
        "NetEarth One": "NetEarthOne",
        "CentralNic": "CentralNic",
        "OVH SAS": "OVH",
        "Crazy Domains": "CrazyDomains",
        "123-reg": "123-reg",
        "Hover": "Hover",
        "Domain.com": "Domain.com",
        "R01": "R01",
        "Joker.com": "Joker",
        "Wild West Domains": "WildWestDomains",
        "PublicDomainRegistry": "PDR",
        "Russia RU-CENTER": "RU-CENTER",
        "REG.RU": "REG.RU",
        "RU-CENTER": "RU-CENTER",
        "Internet.bs": "Internet.bs",
        "Infomaniak": "Infomaniak",
        "Crazy Domains Pty": "CrazyDomains",
        "InternetX": "InternetX",
        "Net4India": "Net4India",
        "HostGator": "HostGator",
        "IP Mirror": "IP Mirror",
        "Kheweul.com": "Kheweul",
        "Lexsynergy": "Lexsynergy",
        "Misk.com": "Misk",
        "Nominet": "Nominet",
        "OpenProvider": "OpenProvider",
        "Paragon Internet Group": "ParagonInternet",
        "Planethoster": "Planethoster",
        "Ripe NCC": "Ripe NCC",
        "Sedo": "Sedo",
        "Shinjiru": "Shinjiru",
        "Vautron Rechenzentrum": "Vautron",
        "Webnames": "Webnames",
        "ZNet Technologies": "ZNetTech",
    }

    return known_brands.get(name.title(), name.title())


# Open domain input file
filename = open('input.txt')
lines = filename.readlines()
domains = [line.strip() for line in lines]

# Define API Calls
domain_to_ip_api = f"https://api.threatintelligenceplatform.com/v1/infrastructureAnalysis?apiKey" \
                   f"={threatint_key}&domainName="
whois_api = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={whois_key}" \
            f"&outputformat=JSON&domainName="

# Open file to write CSV file
with open('output.csv', 'w', newline='', encoding='utf-8') as outfile:
    w = csv.writer(outfile, dialect=csv.excel)

    for domain in domains:
        print(f"Checking: {domain}")

        # Initialize fields
        createdDate = registrar = registrar_country = ip_address = nameServers = mx_address = ssl_issuer = "N/A"

        try:
            # GET IP data
            response = urlopen(domain_to_ip_api + domain)
            data_json = json.loads(response.read())

            ip_country = fix_case(data_json[0]["geolocation"]["country"]) if data_json else "N/A"

            ip_address = []
            for record in data_json:
                if record["resourceType"] == "web":
                    ip_address.append(record["ipv4"])
                    break
            if not ip_address:
                ip_address = "N/A"

            mx_address = []
            for record in data_json:
                if record["resourceType"] == "MX":
                    mx_address.append(record["domainName"])
                    break
            if not mx_address:
                mx_address = "No Records"
        except (KeyError, json.JSONDecodeError, Exception):
            ip_country, ip_address, mx_address = "N/A", "N/A", "No Records"

        try:
            # GET Domain Data
            response = urlopen(whois_api + domain)
            data_json = json.loads(response.read())

            whois_data = data_json.get("WhoisRecord", {})
            createdDate = whois_data.get("registryData", {}).get("createdDate", "N/A").split("T")[0]

            registrar = whois_data.get("registrarName", "N/A").replace(",", ".", 2)
            registrar = clean_registrar(registrar)

            registrar_country = fix_case(whois_data.get("registrant", {}).get("country", "N/A"))

            # Only grab the first name server
            name_servers_list = whois_data.get("nameServers", {}).get("hostNames", [])
            nameServers = name_servers_list[0] if name_servers_list else "N/A"

        except (KeyError, json.JSONDecodeError, Exception):
            pass  # Retain initialized "N/A" values if request fails

        # Get SSL Issuer
        ssl_issuer = get_issuer(domain.strip("\n"))
        ssl_rank = switch(ssl_issuer)

        # Format lists to multiline text
        ip_address = format_list(ip_address)
        mx_address = format_list(mx_address)

        # Write to CSV
        w.writerow([domain, createdDate, registrar, registrar_country, ip_address, nameServers, mx_address, ssl_rank])