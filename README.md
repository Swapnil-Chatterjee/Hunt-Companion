An application that searches for Splunk/Sentinel Rules, IoCs & TTPs for detecting threat actors, malwares and other breaches.  


Steps to Run:
Install VS Code: Download Visual Studio Code from official site - https://code.visualstudio.com/download
Install Python: You can download prefered version of Python 3 from MS Store - https://apps.microsoft.com/detail/9NRWMJP3717K?hl=en-us&gl=IN&ocid=pdpshare (Python 3.11)
Install the Python Extension: Go to the Extensions tab (or press Ctrl+Shift+X), search for "Python", and install the Python extension by Microsoft
Select Python Interpreter (if not selected by default): Click on the Python version in the bottom-left corner of the VS Code window and select the interpreter you installed
Download Hunt Companion: Go to GitHub page of Hunt Companion and download zip-  https://github.com/Swapnil-Chatterjee/Hunt-Companion/archive/refs/heads/main.zip
Unzip and open the folder in VS Code. 
Open Terminal: Go to Terminal menu-> New Terminal
Run installation for requirements: In terminal go to the sub-folder containing the requirements file(Hunt-Companion/my_web_project) and then type command pip install -r requirements.txt
Download the Sigma Rules from GitHub: Download the zip from SigmaHQ/sigma page - https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip
Unzip the Sigma Rules' downloaded zip and copy the full path (e.g- C:\Program Files\Sigma_Rules) where you unzipped.
Go to the opened folder in VS Code and Create a file config.py (under main folder Hunt-Companion/my_web_project) 
Add DIRECTORY_PATH and API_KEY from VT Enterprise in the config file
  API_KEY="Paste your API key here"
  DIRECTORY_PATH=f"C:\Program Files\Sigma_Rules(replace copied path of Sigma Rules)"
Run the program from terminal using command "python app.py"

