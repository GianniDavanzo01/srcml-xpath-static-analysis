from flask import Flask, request 
import yaml 
  
app = Flask(__name__) 
  
 # Function to load YAML payload into a dictionary 
def load_yaml_payload(yaml_data): 
     try: 
         data_dict = yaml.safe_load(yaml_data) 
         if isinstance(data_dict, dict): 
             return data_dict 
         else: 
             return {"error": "Invalid YAML format. Expected a dictionary."} 
     except Exception as e: 
         return {"error": f"Error loading YAML: {str(e)}"} 
  
@app.route('/load_yaml', methods=['POST']) 
def load_yaml(): 
     try: 
         # Get the YAML payload from the request data 
         yaml_data = request.data.decode('utf-8') 
  
         # Load the YAML payload into a dictionary using the function 
         result = load_yaml_payload(yaml_data) 
  
         return result 
     except Exception as e: 
         return {"error": f"An error occurred: {str(e)}"} 
  
if __name__ == '__main__': 
     app.run(debug=True)
