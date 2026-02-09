import re 
from difflib import SequenceMatcher 

trusted_domains = ["paypal.com", "google.com", "amazon.com", "microsoft.com"]

with open("pro2.txt",'r') as file : 
    data = file.read().lower() 

score = 0

if "spf=fail" in data:
    score += 1 
    print('failed in spf')
if "dkim=fail" in data: 
    score += 1
    print('failed in dkim')
if "dmarc=fail" in data: 
    score += 1
    print('failed in dmarc ')

ips = re.search(r"\d+\.\d+\.\d+\.\d+", data) 
ip = ips.group() if ips else "unknown"

datamail = re.search(r"from:.*@([\w\.-]+)", data)
domain = datamail.group(1)

urls = re.findall(r"https?://[^\s]+", data)
if urls: 
    score += 1 
    print("suspisious url founded ",urls)

def lookalike(domain):
    for trusted in trusted_domains: 
        s= SequenceMatcher(None, domain, trusted).ratio() 
        if s >= 0.9 and domain != trusted:
            return True , trusted
    return False , None 

isnot , matched = lookalike(domain)
if isnot == True : 
    print("might be a phisher \n")
    print("domain name close to " , matched )

#final scoring 
if score >= 4:
    print(" HIGH RISK PHISHING EMAIL",score)
elif score >= 2:
    print(" POSSIBLE PHISHING")
else:
    print(" Email looks safe")
