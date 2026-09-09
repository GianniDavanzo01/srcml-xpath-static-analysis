from flask import Flask, request 
import os 
  
app = Flask(__name__) 
  
@app.route('/ping_url', methods=['GET']) 
def ping_url(): 
     # Get the 'url_ping' parameter from the request 
     url_ping = request.args.get('url_ping') 
  
     # Check if the 'url_ping' parameter is provided 
     if not url_ping: 
         return "Parameter 'url_ping' is missing from the request." 
  
     try: 
         # Use the os.system() function to run the ping command 
         command = f"ping -c 4 {url_ping}"  # Ping 4 times for demonstration 
         response = os.system(command) 
  
         # Check the response code to determine success or failure 
         if response == 0: 
             exec_ping = f"Ping to {url_ping} was successful." 
         else: 
             exec_ping = f"Ping to {url_ping} failed." 
  
         return exec_ping 
     except Exception as e: 
         return f"An error occurred: {str(e)}" 
  
if __name__ == '__main__': 
     app.run(debug=True)
