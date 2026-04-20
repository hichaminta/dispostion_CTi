import os
import json
import ipaddress
import csv
import io
import requests
import zipfile
import glob
import shutil

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GEO_BASE = os.path.join(BASE_DIR, "geo_base.json")
TEMP_DIR = os.path.join(BASE_DIR, "temp_sources")
DATA_DIR = os.path.join(BASE_DIR, "temp_ip_data")

# URLs
IPVERSE_ZIP_URL = "https://github.com/ipverse/country-ip-blocks/archive/refs/heads/master.zip"
RIR_STATS_URLS = {
    "AFRINIC": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    "APNIC": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "ARIN": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "LACNIC": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "RIPE": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
}

# IP2Location Sample
IP2LOCATION_SAMPLE = """
"0","16777215","-","-"
"16777216","16777471","AU","Australia"
"16777472","16778239","CN","China"
"16778240","16779263","AU","Australia"
"16779264","16781311","CN","China"
"16781312","16785407","JP","Japan"
"16785408","16793599","CN","China"
"16793600","16809983","JP","Japan"
"16809984","16842751","TH","Thailand"
"16842752","16843007","CN","China"
"16843008","16843263","AU","Australia"
"16843264","16859135","CN","China"
"16859136","16875519","JP","Japan"
"16875520","16908287","TH","Thailand"
"16908288","16909055","CN","China"
"16909056","16909311","UA","Ukraine"
"16909312","16941055","CN","China"
"16941056","16973823","TH","Thailand"
"16973824","17039359","CN","China"
"17039360","17039615","AU","Australia"
"17039616","17072127","CN","China"
"17072128","17104895","TH","Thailand"
"17104896","17170431","JP","Japan"
"17170432","17279148","IN","India"
"17279149","17279149","SG","Singapore"
"17279150","17301503","IN","India"
"17301504","17367039","CN","China"
"17301504","17279150","IN","India"
"17367040","17432575","MY","Malaysia"
"17432576","17435135","CN","China"
"17435136","17435391","IN","India"
"17435392","17465343","CN","China"
"17465344","17498111","TH","Thailand"
"17498112","17563647","KR","Korea (the Republic of)"
"17563648","17825791","CN","China"
"17825792","17842175","KR","Korea (the Republic of)"
"17842176","17986559","-","-"
"17986560","18087935","KR","Korea (the Republic of)"
"18087936","18153471","TH","Thailand"
"18153472","18210815","JP","Japan"
"18210816","18219007","SG","Singapore"
"18219008","18350079","IN","India"
"18350080","18874367","CN","China"
"18874368","18907135","MY","Malaysia"
"18923520","18925567","HK","Hong Kong"
"18925568","18926079","SG","Singapore"
"18926080","18926187","TW","Taiwan (Province of China)"
"18926188","18926188","SG","Singapore"
"18926189","18926207","TW","Taiwan (Province of China)"
"18926208","18926335","SG","Singapore"
"18926336","18926336","TW","Taiwan (Province of China)"
"18926337","18926337","SG","Singapore"
"18926338","18926428","TW","Taiwan (Province of China)"
"18926429","18926429","SG","Singapore"
"18926430","18926463","TW","Taiwan (Province of China)"
"18926464","18926591","SG","Singapore"
"18926592","18926684","TW","Taiwan (Province of China)"
"18926685","18926685","SG","Singapore"
"18926686","18926719","TW","Taiwan (Province of China)"
"18926720","18926847","SG","Singapore"
"18926848","18927103","HK","Hong Kong"
"18927104","18927615","SG","Singapore"
"18927616","18929663","TW","Taiwan (Province of China)"
"18929664","18930175","KR","Korea (the Republic of)"
"18930176","18930687","HK","Hong Kong"
"18930688","18930943","TW","Taiwan (Province of China)"
"18930944","18931455","HK","Hong Kong"
"18931456","18933759","JP","Japan"
"18933760","18935807","US","United States of America"
"18935808","18938879","HK","Hong Kong"
"18938880","18939135","KH","Cambodia"
"18939136","18939903","HK","Hong Kong"
"18939904","18994630","JP","Japan"
"18994631","18994635","BR","Brazil"
"18994636","18994657","JP","Japan"
"18994658","18994662","BR","Brazil"
"18994663","19005439","JP","Japan"
"19005440","19136511","TW","Taiwan (Province of China)"
"19136512","19202047","HK","Hong Kong"
"19202048","19267583","PH","Philippines"
"19267584","19398655","IN","India"
"19398656","19726335","AU","Australia"
"19726336","19791871","CN","China"
"19791872","19922943","TH","Thailand"
"19922944","20185087","CN","China"
"20185088","20248330","VN","Viet Nam"
"20248331","20248331","SG","Singapore"
"20248332","20447231","VN","Viet Nam"
"20447232","20971519","CN","China"
"20971520","21102591","HK","Hong Kong"
"21102592","21233663","JP","Japan"
"21233664","21495807","CN","China"
"21495808","22020095","JP","Japan"
"22020096","23068671","CN","China"
"23068672","24117247","KR","Korea (the Republic of)"
"24117248","24379391","JP","Japan"
"24379392","24510463","CN","China"
"24510464","24518655","HK","Hong Kong"
"24518656","24519679","NL","Netherlands (Kingdom of the)"
"24519680","24526847","HK","Hong Kong"
"24526848","24535039","SG","Singapore"
"24535040","24575999","HK","Hong Kong"
"24576000","24641535","CN","China"
"24641536","27262975","AU","Australia"
"27262976","28311551","TW","Taiwan (Province of China)"
"28311552","28442623","KR","Korea (the Republic of)"
"28442624","28443135","US","United States of America"
"28443136","28443647","AU","Australia"
"28443648","28444415","US","United States of America"
"28444416","28444671","IE","Ireland"
"28444672","28445183","US","United States of America"
"28445184","28445439","DE","Germany"
"28445440","28445695","AU","Australia"
"28445696","28446719","US","United States of America"
"28446720","28446975","BH","Bahrain"
"28446976","28447231","IT","Italy"
"28447232","28447487","ZA","South Africa"
"28447488","28447743","ID","Indonesia"
"28447744","28447999","AE","United Arab Emirates"
"28448000","28448255","CH","Switzerland"
"28448256","28448511","ES","Spain"
"28448512","28448767","IN","India"
"28448768","28449023","AU","Australia"
"28449024","28449279","IL","Israel"
"28449280","28449535","CA","Canada"
"28449536","28449791","NZ","New Zealand"
"28449792","28450047","TH","Thailand"
"28450048","28450303","MX","Mexico"
"28450304","28450559","US","United States of America"
"28450560","28450815","TW","Taiwan (Province of China)"
"28450816","28454911","BR","Brazil"
"28454912","28459007","AR","Argentina"
"28459008","28459263","JP","Japan"
"28459264","28459519","US","United States of America"
"28459520","28460031","AU","Australia"
"28460032","28463103","US","United States of America"
"28463104","28463359","AU","Australia"
"28463360","28463615","US","United States of America"
"28463616","28464639","AU","Australia"
"28464640","28465151","US","United States of America"
"28465152","28465407","IN","India"
"28465408","28465663","SG","Singapore"
"28465664","28465919","FR","France"
"28465920","28466175","KR","Korea (the Republic of)"
"28466176","28466431","CA","Canada"
"28466432","28466687","SE","Sweden"
"28466688","28466943","GB","United Kingdom of Great Britain and Northern Ireland"
"28466944","28467199","BR","Brazil"
"28467200","28468223","AU","Australia"
"28468224","28468479","US","United States of America"
"28468480","28468735","JP","Japan"
"28468736","28468991","MY","Malaysia"
"28468992","28469247","HK","Hong Kong"
"28469248","28471295","US","United States of America"
"28471296","28479487","PS","Palestine, State of"
"28479488","28487167","US","United States of America"
"28487168","28487423","SE","Sweden"
"28487424","28488703","AU","Australia"
"28488704","28495871","US","United States of America"
"28495872","28499967","PS","Palestine, State of"
"28499968","28508159","ES","Spain"
"28508160","28508671","AU","Australia"
"28508672","28509183","US","United States of America"
"28509184","28511743","AU","Australia"
"28511744","28512255","US","United States of America"
"28512256","28514303","AU","Australia"
"28514304","28518399","US","United States of America"
"28518400","28520447","PS","Palestine, State of"
"28520448","28521471","AU","Australia"
"28521472","28524031","US","United States of America"
"28524032","28524543","AU","Australia"
"28524544","28526591","US","United States of America"
"28526592","28528639","PS","Palestine, State of"
"28528640","28530687","US","United States of America"
"28530688","28532735","PS","Palestine, State of"
"28532736","28533759","AU","Australia"
"28533760","28536831","US","United States of America"
"28536832","28540927","FR","France"
"28540928","28573695","TH","Thailand"
"28573696","28966911","CN","China"
"28966912","29032447","GB","United Kingdom of Great Britain and Northern Ireland"
"29032448","29097983","IN","India"
"29097984","29884415","CN","China"
"29884416","29949951","TW","Taiwan (Province of China)"
"29949952","30015487","KR","Korea (the Republic of)"
"30015488","30408703","CN","China"
"30408704","33554431","KR","Korea (the Republic of)"
"33554432","33751039","US","United States of America"
"34603008","34603263","BR","Brazil"
"34603264","34603519","DE","Germany"
"34603520","34603775","CZ","Czechia"
"34603776","34604543","BE","Belgium"
"34604544","34605055","NL","Netherlands (Kingdom of the)"
"34605056","34605311","ES","Spain"
"34612480","34612735","GB","United Kingdom of Great Britain and Northern Ireland"
"34612736","34613247","ES","Spain"
"34613248","34613503","BE","Belgium"
"34613504","34613759","DE","Germany"
"34613760","34614271","NL","Netherlands (Kingdom of the)"
"34614272","34614527","AE","United Arab Emirates"
"34614528","34614783","BE","Belgium"
"34614784","34615295","DE","Germany"
"34615296","34615551","FR","France"
"34615552","34616319","BE","Belgium"
"34616320","34616575","DE","Germany"
"34616832","34617087","ES","Spain"
"""

def ensure_dirs():
    if not os.path.exists(TEMP_DIR): os.makedirs(TEMP_DIR)
    if not os.path.exists(DATA_DIR): os.makedirs(DATA_DIR)

def download_file(url, target_path):
    print(f"Downloading {url}...")
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        with open(target_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False

def fetch_ipverse():
    zip_path = os.path.join(TEMP_DIR, "ipverse.zip")
    if download_file(IPVERSE_ZIP_URL, zip_path):
        print("Extracting IPVerse data...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(DATA_DIR)
        
        # The zip contains a directory like 'country-ip-blocks-master'
        extracted_dirs = [d for d in os.listdir(DATA_DIR) if os.path.isdir(os.path.join(DATA_DIR, d)) and 'country-ip-blocks' in d]
        if extracted_dirs:
            src_path = os.path.join(DATA_DIR, extracted_dirs[0])
            dest_path = os.path.join(DATA_DIR, "country")
            
            # Use a more robust move on Windows
            try:
                if os.path.exists(dest_path):
                    shutil.rmtree(dest_path, ignore_errors=True)
                shutil.move(src_path, dest_path)
                print(f"IPVerse data ready in {dest_path}")
                return True
            except Exception as e:
                print(f"Warning during move: {e}. Data might already be in place.")
                return os.path.exists(dest_path)
    return False

def fetch_rir_stats():
    rir_files = []
    for reg, url in RIR_STATS_URLS.items():
        path = os.path.join(TEMP_DIR, f"delegated-{reg.lower()}.txt")
        if download_file(url, path):
            rir_files.append(path)
    return rir_files

def parse_ip2location_csv(csv_content, source_name="IP2Location"):
    ranges = []
    reader = csv.reader(io.StringIO(csv_content.strip()))
    for row in reader:
        if len(row) >= 3:
            try:
                start = int(row[0])
                end = int(row[1])
                cc = row[2]
                if cc and cc != "-":
                    ranges.append([start, end, cc, source_name])
            except: continue
    return ranges

def parse_rir_stats(file_path):
    ranges = []
    print(f"Parsing RIR file: {file_path}")
    source_name = f"RIR ({os.path.basename(file_path)})"
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("#") or not line.strip(): continue
                parts = line.split("|")
                # Format: registry|cc|type|start|value|date|status|...
                if len(parts) >= 7 and parts[2] == "ipv4":
                    cc = parts[1].upper()
                    if cc == "*" or not cc: continue
                    start_ip_str = parts[3]
                    count_str = parts[4]
                    status = parts[6]
                    if status in ["assigned", "allocated"]:
                        try:
                            start_ip = int(ipaddress.IPv4Address(start_ip_str))
                            count = int(count_str)
                            end_ip = start_ip + count - 1
                            ranges.append([start_ip, end_ip, cc, source_name])
                        except: pass
    except Exception as e:
        print(f"Error parsing {file_path}: {e}")
    return ranges

def parse_ipverse_data():
    ranges = []
    file_pattern = os.path.join(DATA_DIR, "country", "**", "ipv4-aggregated.txt")
    files = glob.glob(file_pattern, recursive=True)
    print(f"Adding IPVerse data from {len(files)} country files...")
    for file_path in files:
        cc = os.path.basename(os.path.dirname(file_path)).upper()
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                cidr = line.strip()
                if not cidr or cidr.startswith("#"): continue
                try:
                    net = ipaddress.ip_network(cidr)
                    if net.version == 4:
                        ranges.append([int(net.network_address), int(net.broadcast_address), cc, "IPVerse"])
                except: pass
    return ranges

def int_to_ip(ip_int):
    return str(ipaddress.IPv4Address(ip_int))

def save_compact_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("{\n")
        f.write('    "ips": ' + json.dumps(data.get("ips", {}), indent=4).replace("\n", "\n    ") + ",\n")
        f.write('    "ranges": [\n')
        ranges = data.get("ranges", [])
        for i, r in enumerate(ranges):
            comma = "," if i < len(ranges) - 1 else ""
            formatted_range = [
                int_to_ip(r[0]),
                int_to_ip(r[1]),
                r[2],
                r[3]
            ]
            f.write(f'        {json.dumps(formatted_range)}{comma}\n')
        f.write("    ]\n")
        f.write("}\n")

def process_all():
    ensure_dirs()
    all_ranges = []
    
    # 1. IP2Location (Sample)
    print("Processing IP2Location sample...")
    all_ranges.extend(parse_ip2location_csv(IP2LOCATION_SAMPLE, "IP2Location Sample"))
    
    # 2. IPVerse
    # Download if not present or just download anyway for latest
    print("Fetching IPVerse data...")
    fetch_ipverse()
    all_ranges.extend(parse_ipverse_data())

    # 3. RIR Stats
    print("Fetching RIR stats...")
    rir_files = fetch_rir_stats()
    for rf in rir_files:
        all_ranges.extend(parse_rir_stats(rf))
        
    print(f"Total ranges collected: {len(all_ranges)}")
    
    # Sort
    print("Sorting ranges...")
    all_ranges.sort(key=lambda x: x[0])
    
    # Load existing static IPS cache if any
    ips_cache = {}
    if os.path.exists(GEO_BASE):
        try:
            with open(GEO_BASE, "r", encoding="utf-8") as f:
                old_data = json.load(f)
                ips_cache = old_data.get("ips", {})
        except: pass

    final_data = {
        "ips": ips_cache,
        "ranges": all_ranges
    }
    
    print(f"Saving {len(all_ranges)} ranges to {GEO_BASE}...")
    save_compact_json(final_data, GEO_BASE)
    print("Ingestion complete.")

if __name__ == "__main__":
    process_all()
