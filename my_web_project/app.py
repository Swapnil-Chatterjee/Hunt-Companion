from flask import Flask, render_template, request
import requests, os, glob, yaml, urllib.parse
from config import API_KEY, DIRECTORY_PATH
app = Flask(__name__)

url = "https://www.virustotal.com"
query="/api/v3/threat_actors"
headers = {
            "accept": "application/json",
            "X-Apikey": API_KEY
        }
                

@app.route('/', methods=['GET', 'POST'])
def index():
        
    # Redirect to GET request to avoid resubmission on page refresh
    return render_template('index.html')
    
# Subpage 1 Display List of Threat actors as per filters
@app.route('/threat_actors', methods=['GET', 'POST'])
def threat_actors():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        source_region = request.form['source_region']
        targeted_industry = request.form['targeted_industry']
        targeted_region = request.form['targeted_region']
        order = request.form['order']
        
        # Log the submitted data
        # app.logger.info(f"Submitted Data: Name - {name})
        
        # Process the submitted data here if needed
        submitted_data = {'name': name, 'description':description, 'source_region':source_region, 'targeted_industry':targeted_industry, 'targeted_region':targeted_region, 'order':order}

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
        
        
        # response = ""
        # print(url+query)
        response = requests.get(url+query1, headers=headers)
        response = response.json()
        # print(response.text)

        threat_actors = []

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

        # Get VirusTotal collections
        # collections = get_virustotal_collections(API_KEY)
    
        return render_template('GET_TA.html', submitted_data=submitted_data,threat_actors=threat_actors)
    
    return render_template('GET_TA.html')

#Render Threat Actor TTPs
@app.route('/threat_actor/<actor_id>&<actor_name>')
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
    

if __name__ == '__main__':
    app.run(debug=True)
