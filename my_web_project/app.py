from flask import Flask, render_template, request
import json

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        
        # Log the submitted data
        app.logger.info(f"Submitted Data: Name - {name}, Email - {email}")
        
        # Process the submitted data here if needed
        submitted_data = {'name': name, 'email': email}

        # Redirect to GET request to avoid resubmission on page refresh
        return render_template('index.html', submitted_data=submitted_data)
    
    # If GET request or initial load, display existing data
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
