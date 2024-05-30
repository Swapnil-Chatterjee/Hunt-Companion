from flask import Flask, render_template, request
import requests, os, glob, yaml, urllib.parse, subprocess, pycountry, datetime 
from sigma.rule import SigmaRule
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from config import API_KEY, DIRECTORY_PATH
app = Flask(__name__)

url = "https://www.virustotal.com"
query="/api/v3/threat_actors"
sub="/api/v3/collections"
headers = {
            "accept": "application/json",
            "X-Apikey": API_KEY
        }
                

@app.route('/', methods=['GET', 'POST'])
def index():
        
    # Redirect to GET request to avoid resubmission on page refresh
    return render_template('index.html')

def get_country_alpha2(country_name):
    try:
        country = pycountry.countries.get(name=country_name)
        if country:
            return country.alpha_2
        else:
            return country_name
    except LookupError:
        return False

# Subpage 1 Display List of Threat actors as per filters
@app.route('/threat_actors', methods=['GET', 'POST'])
def threat_actors():
    try:
        country_names = [country.name for country in pycountry.countries]
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            source_region = request.form['source_region']
            targeted_industry = request.form['targeted_industry']
            targeted_region = request.form['targeted_region']
            order = request.form['order']

            # Log the submitted data
            # app.logger.info(f"Submitted Data: Name - {name})
            error_message = None
            if targeted_region or source_region:
                targeted_region=get_country_alpha2(targeted_region)
                source_region=get_country_alpha2(source_region)
                if targeted_region==False or source_region==False:
                    error_message="Error in input region"
            # Process the submitted data here if needed
            submitted_data ={'name': name, 'description':description, 'source_region': source_region, 'targeted_industry':targeted_industry, 'targeted_region':targeted_region, 'order':order}
            
            # query="/api/v3/threat_actors?filter=targeted_region:US&order=last_seen_date-"
            
            filter = "" 

            for key, value in submitted_data.items():
                if(f"{value}"!=""):
                    if(filter!=""):
                        filter+="&"
                    if(f"{key}"=="order") :
                        filter += f"{key}={value}"
                    else:
                        filter += f"{key}:{value}"
                
            if(filter!=""):
                query1=query+"?filter="+filter+"-"
            
            threat_actors = []
            next_link=url+query1

            while next_link:
                # response = ""
                print(next_link)
                response = requests.get(next_link, headers=headers)
                response = response.json()
                # print(response.text)

                for threat_actor in response["data"]:
                    name = threat_actor["attributes"].get("name")
                    description = threat_actor["attributes"].get("description")
                    targeted_industries = threat_actor["attributes"].get("targeted_industries")
                    actor_id = threat_actor["id"]

                    if name:
                        actor_info = {
                            "name": name,
                            "description": description,
                            "targeted_industries": targeted_industries,
                            "id": actor_id
                        }
                    threat_actors.append(actor_info)
                    # print(threat_actors)
                
                next_link = response.get("links", {}).get("next")

            return render_template('GET_TA.html', submitted_data=submitted_data,threat_actors=threat_actors, country_names=country_names, error_message=error_message)
        
        return render_template('GET_TA.html', country_names=country_names)

    except Exception as e:    
        return render_template('GET_TA.html', country_names=country_names, error_message=e)

#Render Threat Actor TTPs
@app.route('/threat_actor/ttps/<actor_id>&<actor_name>')
def threat_actor_ttps(actor_id, actor_name):
    # Fetch details for a specific threat actor based on the actor_id
    # Perform GET request or fetch data using the actor_id
    # response = requests.get(url+query+"/"+actor_id+"/attack_techniques", headers=headers)
    
    all_ttps = []
    next_link = url+query+"/"+actor_id+"/attack_techniques"

    while next_link:
        response = requests.get(next_link, headers=headers)
        data = response.json()
    
        for item in data.get("data", []):
            ttp_info = {
                "id": item.get("id"),
                "name": item["attributes"].get("name")
            }
            # print(ttp_info)
            all_ttps.append(ttp_info)

        next_link = data.get("links", {}).get("next")

    return render_template('TA_TTP.html', all_ttps=all_ttps, actor_name=actor_name)

#Render Threat Actor IOCs
@app.route('/threat_actor/iocs/<actor_id>&<actor_name>')
def threat_actor_iocs(actor_id, actor_name):
    # Fetch details for a specific threat actor based on the actor_id
    # Perform GET request or fetch data using the actor_id
    #"https://www.virustotal.com/api/v3/threat_actors/03c80674-35f8-4fe0-be2b-226ed0fcd69f/related_domains?limit=10"

    all_files = []
    url_files = url+query+"/"+actor_id+"/related_files?limit=10"
    response = requests.get(url_files, headers=headers)
    data = response.json()

    for item in data.get("data", []):
        file_info = {
            "id": item.get("id"),
            "type": item.get("type"),
            "size": item["attributes"].get("size"),
            "sha256": item["attributes"].get("sha256"),
            "first_seen_itw_date": item["attributes"].get("first_seen_itw_date"),
            "last_submission_date": item["attributes"].get("last_submission_date"),
            "times_submitted": item["attributes"].get("times_submitted"),
            "malicious": item["attributes"]["last_analysis_stats"].get("malicious"),
            "suspicious": item["attributes"]["last_analysis_stats"].get("suspicious"),
            "undetected": item["attributes"]["last_analysis_stats"].get("undetected"),
            "harmless": item["attributes"]["last_analysis_stats"].get("harmless"),
            "timeout": item["attributes"]["last_analysis_stats"].get("timeout")
            
        }

        file_info["first_seen_itw_date"]= datetime.date.fromtimestamp(file_info["first_seen_itw_date"]) if file_info["first_seen_itw_date"] else None
        file_info["last_submission_date"]= datetime.date.fromtimestamp(file_info["last_submission_date"]) if file_info["last_submission_date"] else None
        file_info["positive_hits"]= file_info["malicious"] + file_info["suspicious"]
        file_info["total"]= file_info["malicious"] + file_info["suspicious"] + file_info["undetected"] + file_info["harmless"]+file_info["timeout"]
        
        # print(file_info)
        all_files.append(file_info)

    
    all_ips = []
    url_ips = url+query+"/"+actor_id+"/related_ip_addresses?limit=10"
    response = requests.get(url_ips, headers=headers)
    data = response.json()

    for item in data.get("data", []):
        ip_info = {
            "id": item.get("id"),
            "type": item.get("type"),
            "country": item["attributes"].get("country"),
            "asn": item["attributes"].get("asn"),
            "as_source": item["attributes"].get("as_owner"),
            "malicious": item["attributes"]["last_analysis_stats"].get("malicious"),
            "suspicious": item["attributes"]["last_analysis_stats"].get("suspicious"),
            "undetected": item["attributes"]["last_analysis_stats"].get("undetected"),
            "harmless": item["attributes"]["last_analysis_stats"].get("harmless"),
            "timeout": item["attributes"]["last_analysis_stats"].get("timeout")
            
        }

        ip_info["positive_hits"]= ip_info["malicious"] + ip_info["suspicious"]
        ip_info["total"]= ip_info["malicious"] + ip_info["suspicious"] + ip_info["undetected"] + ip_info["harmless"]+ip_info["timeout"]
        
        # print(ip_info)
        all_ips.append(ip_info)

    all_domains = []
    url_domains = url+query+"/"+actor_id+"/related_domains?limit=10"
    response = requests.get(url_domains, headers=headers)
    data = response.json()

    for item in data.get("data", []):
        domain_info = {
            "id": item.get("id"),
            "type": item.get("type"),
            "last_update": item["attributes"].get("last_update_date"),
            "creation_date": item["attributes"].get("creation_date"),
            "registrar": item["attributes"].get("registrar"),
            "malicious": item["attributes"]["last_analysis_stats"].get("malicious"),
            "suspicious": item["attributes"]["last_analysis_stats"].get("suspicious"),
            "undetected": item["attributes"]["last_analysis_stats"].get("undetected"),
            "harmless": item["attributes"]["last_analysis_stats"].get("harmless"),
            "timeout": item["attributes"]["last_analysis_stats"].get("timeout")
            
        }

        domain_info["last_update"]= datetime.date.fromtimestamp(domain_info["last_update"]) if domain_info["last_update"] else None
        domain_info["creation_date"]= datetime.date.fromtimestamp(domain_info["creation_date"]) if domain_info["creation_date"] else None
        domain_info["positive_hits"]= domain_info["malicious"] + domain_info["suspicious"]
        domain_info["total"]= domain_info["malicious"] + domain_info["suspicious"] + domain_info["undetected"] + domain_info["harmless"]+domain_info["timeout"]
        
        # print(domain_info)
        all_domains.append(domain_info)

    all_urls = []
    url_urls = url+query+"/"+actor_id+"/related_urls?limit=10"
    response = requests.get(url_urls, headers=headers)
    data = response.json()

    for item in data.get("data", []):
        url_info = {
            "id": item.get("id"),
            "type": item.get("type"),
            "url": item["attributes"].get("url"),
            "first_submission_date": item["attributes"].get("first_submission_date"),
            "last_submission_date": item["attributes"].get("last_submission_date"),
            "times_submitted": item["attributes"].get("times_submitted"),
            "malicious": item["attributes"]["last_analysis_stats"].get("malicious"),
            "suspicious": item["attributes"]["last_analysis_stats"].get("suspicious"),
            "undetected": item["attributes"]["last_analysis_stats"].get("undetected"),
            "harmless": item["attributes"]["last_analysis_stats"].get("harmless"),
            "timeout": item["attributes"]["last_analysis_stats"].get("timeout")
            
        }

        url_info["first_submission_date"]= datetime.date.fromtimestamp(url_info["first_submission_date"]) if url_info["first_submission_date"] else None
        url_info["last_submission_date"]= datetime.date.fromtimestamp(url_info["last_submission_date"]) if url_info["last_submission_date"] else None
        url_info["positive_hits"]= url_info["malicious"] + url_info["suspicious"]
        url_info["total"]= url_info["malicious"] + url_info["suspicious"] + url_info["undetected"] + url_info["harmless"]+url_info["timeout"]
        
        # print(url_info)
        all_urls.append(url_info)

    
    return render_template('TA_IOC.html', all_files=all_files, all_urls=all_urls, all_ips=all_ips, all_domains=all_domains, actor_name=actor_name)

#Render Threat Actor References
@app.route('/threat_actor/refs/<actor_id>&<actor_name>')
def threat_actor_refs(actor_id, actor_name):
    # Fetch details for a specific threat actor based on the actor_id
    # Perform GET request or fetch data using the actor_id
    #"https://www.virustotal.com/api/v3/threat_actors/03c80674-35f8-4fe0-be2b-226ed0fcd69f/related_domains?limit=10"

    all_refs = []
    url_refs = url+query+"/"+actor_id+"/references?limit=10"
    response = requests.get(url_refs, headers=headers)
    data = response.json()

    for item in data.get("data", []):
        ref_info = {
            "title": item["attributes"].get("title"),
            "url": item["attributes"].get("url"),
            "author": item["attributes"].get("author"),
            "creation_date": item["attributes"].get("creation_date"),
            
        }

        ref_info["creation_date"]= datetime.date.fromtimestamp(ref_info["creation_date"]) if ref_info["creation_date"] else None
        
        # print(ref_info)
        all_refs.append(ref_info)
  
    return render_template('TA_REFS.html', all_refs=all_refs, actor_name=actor_name)

#Render Threat Actor TTPs
@app.route('/threat_actor/details/<actor_id>&<actor_name>')
def threat_actor_details(actor_id, actor_name):
    # Fetch details for a specific threat actor based on the actor_id
    # Perform GET request or fetch data using the actor_id
    # response = requests.get(url+query+"/"+actor_id+"/attack_techniques", headers=headers)
    
    next_link = url+query+"/"+actor_id

    response = requests.get(next_link, headers=headers)
    data = response.json()

    ta_info = {
        "name": data["data"]["attributes"].get("name"), 
        "aliases": data["data"]["attributes"].get("aliases"),
        "targeted_regions": data["data"]["attributes"].get("targeted_regions"),
        "targeted_industries": data["data"]["attributes"].get("targeted_industries"),
        "description": data["data"]["attributes"].get("description"),
        "sponsor_region": data["data"]["attributes"].get("sponsor_region"),
        "source_region": data["data"]["attributes"].get("source_region"),
        "last_seen_date": data["data"]["attributes"].get("last_seen_date"),
        "last_modification_date": data["data"]["attributes"].get("last_modification_date"),
        "first_seen_date": data["data"]["attributes"].get("first_seen_date")
        
    }
    ta_info["sponsor_region"]=pycountry.countries.get(alpha_2=ta_info["sponsor_region"]).name if ta_info["sponsor_region"] else None
    ta_info["last_seen_date"]= datetime.date.fromtimestamp(ta_info["last_seen_date"]) if ta_info["last_seen_date"] else None
    ta_info["last_modification_date"]= datetime.date.fromtimestamp(ta_info["last_modification_date"]) if ta_info["last_modification_date"] else None
    ta_info["first_seen_date"]= datetime.date.fromtimestamp(ta_info["first_seen_date"]) if ta_info["first_seen_date"] else None
    # print(ttp_info)
        
       
    return render_template('TA_DETAILS.html', ta_info=ta_info, actor_name=actor_name)

# Subpage 1 Display List of Collections as per filters
@app.route('/collections', methods=['GET', 'POST'])
def collections():
    try:
        country_names = [country.name for country in pycountry.countries]
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            owner = request.form['owner']
            source_region = request.form['source_region']
            targeted_industry = request.form['targeted_industry']
            targeted_region = request.form['targeted_region']
            threat_category = request.form['threat_category']
            order = request.form['order']

            # Log the submitted data
            # app.logger.info(f"Submitted Data: Name - {name})
            error_message = None
            if targeted_region or source_region:
                targeted_region=get_country_alpha2(targeted_region)
                source_region=get_country_alpha2(source_region)
                if targeted_region==False or source_region==False:
                    error_message="Error in input region"
            # Process the submitted data here if needed
            submitted_data ={'name': name, 'description':description,'owner':owner,'source_region': source_region, 'targeted_industry':targeted_industry, 'targeted_region':targeted_region, 'threat_category':threat_category, 'order':order}
            
            # query="/api/v3/collections?filter=targeted_region:US&order=last_seen_date-"
            
            filter = "" 

            for key, value in submitted_data.items():
                if(f"{value}"!=""):
                    if(filter!=""):
                        filter+="&"
                    if(f"{key}"=="order") :
                        filter += f"{key}={value}"
                    else:
                        filter += f"{key}:{value}"
                
            if(filter!=""):
                query1=sub+"?limit=10&filter="+filter+"-"
            
            collections = []
            next_link=url+query1

            while next_link:
                # response = ""
                # print(next_link)
                response = requests.get(next_link, headers=headers)
                response = response.json()
                # print(response)

                for collection in response["data"]:
                    name = collection["attributes"].get("name")
                    description = collection["attributes"].get("description")
                    tags = collection["attributes"].get("tags")
                    link = collection["attributes"].get("link")
                    files_count = collection["attributes"].get("files_count")
                    urls_count = collection["attributes"].get("urls_count")
                    domains_count = collection["attributes"].get("domains_count")
                    ip_addresses_count = collection["attributes"].get("ip_addresses_count")
                    references_count = collection["attributes"].get("references_count")
                    collection_id = collection["id"]

                    if name:
                        collection_info = {
                            "name": name,
                            "description": description,
                            "tags": tags,
                            "link":link,
                            "files_count": files_count,
                            "urls_count": urls_count,
                            "domains_count": domains_count,
                            "ip_addresses_count":ip_addresses_count,
                            "references_count":references_count,    
                            "id": collection_id
                        }
                    print(collection_info)
                    collections.append(collection_info)
                    # print(collections)
                
                next_link = None#response.get("links", {}).get("next")

            return render_template('/collections/GET_COL.html', submitted_data=submitted_data,collections=collections, country_names=country_names, error_message=error_message)
        
        return render_template('/collections/GET_COL.html', country_names=country_names)

    except Exception as e:    
        print(e)
        return render_template('/collections/GET_COL.html', country_names=country_names, error_message=e)



# Search rule by ID
@app.route('/search_by_id/<tech_id>')
def search_by_id(tech_id):
    directory_path = DIRECTORY_PATH
    file_type = "yml"
    search_string = tech_id  # Replace with the desired ID tags
    matching_files = []
    
    # Use os.walk to traverse through all directories and subdirectories
    for directory, _, _ in os.walk(directory_path):

        # Create a pattern to match files with the specified file type
        pattern = os.path.join(directory, f'*.{file_type}')

        # Use glob to find files matching the pattern
        for file_path in glob.glob(pattern):
            with open(file_path, 'r', encoding='utf-8') as file:
                try:
                    # yaml_content = yaml.safe_load_all(file)
                    
                    # Use yaml.safe_load_all() to load multiple documents
                    for yaml_content in yaml.safe_load_all(file):
                        if isinstance(yaml_content, dict):
                            
                            #Option 1
                            # Check if the search string is present in the 'tags' field
                            # tags = yaml_content.get('tags', [])
                            # if any(search_string in tag for tag in tags):
                            #     matching_files.append(file_path)
                            
                            #OR---- Option 2
                                
                            # Flatten the YAML content into a list of strings for searching
                            yaml_strings = [str(value) for key, value in yaml_content.items()]
                            # Check if the search_string is present in any of the strings
                            if any(search_string.lower() in yaml_str.lower() for yaml_str in yaml_strings):
                                matching_files.append(file_path)
                except yaml.YAMLError as e:
                    print(f"Error reading YAML in file {file_path}: {e}")
        
    if matching_files:
        count_of_members = len(matching_files)
        print(f"Number of matching files: {count_of_members}")
        print("Matching files:")
        for file_path in matching_files:
            print(file_path)
        
    else:
        print("No matching files found.")
        
    return render_template('GET_YML.html', matching_files= matching_files, tech_id= tech_id)

@app.route('/rules_viewer/<path:filename>')
def rules_viewer(filename):
    try:
        with open(filename, 'r') as file:
            rule = file.read()
        return render_template('RULES_VIEW.html', filename=filename, rule=rule)
    except Exception as e:
        print("Exception:", str(e))
        # Redirect to GET request to avoid resubmission on page refresh
        return render_template('RULES_VIEW.html')

@app.route('/converter/<path:filename>')
def converter(filename):
    try:
        # Load the Sigma rule from the file
        with open(filename, 'r') as file:
            sigma_rule_content = file.read()
        sigma_rule = SigmaRule.from_yaml(sigma_rule_content)

        # Logic to add backend and covert --KQL
        m365def_backend = Microsoft365DefenderBackend()
        kql_rule=m365def_backend.convert_rule(sigma_rule)[0]
        
        # Command to run sigma-cli --SPL
        command = f'sigma convert -t splunk --without-pipeline "{filename}"'
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            spl_rule= result.stdout
        else:
            raise Exception(f"sigma-cli failed: {result.stderr}")

        return render_template('CNVRTD_VIEW.html', title=sigma_rule.title, spl_rule=spl_rule,kql_rule=kql_rule)

    except Exception as e:
        print("Exception:", str(e))
        # Redirect to GET request to avoid resubmission on page refresh
        return render_template('CNVRTD_VIEW.html', title=sigma_rule.title)

if __name__ == '__main__':
    app.run(debug=True)#app.run(host='0.0.0.0', port=5000)
    # from waitress import serve
    # serve(app, host="0.0.0.0", port=8080)