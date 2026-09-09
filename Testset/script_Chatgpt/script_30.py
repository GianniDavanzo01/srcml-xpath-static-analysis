from flask import Flask, request, jsonify 
import yaml 
import re 
  
app = Flask(__name__) 
  
def is_safe_yaml(yaml_str): 
     # Define a list of disallowed YAML tags 
     disallowed_tags = ['!python', '!unsafe', '!'] 
      
     # Check if any disallowed tag is present in the YAML content 
     for tag in disallowed_tags: 
         if re.search(tag, yaml_str): 
             return False 
     return True 
  
@app.route('/load_yaml', methods=['POST']) 
def load_yaml(): 
     try: 
         # Get the YAML content from the request 
         yaml_str = request.data.decode('utf-8') 
          
         # Check for security issues in the YAML content 
         if not is_safe_yaml(yaml_str): 
             return 'Security check failed: Disallowed YAML tags found.' 
          
         # Load the YAML content into a dictionary 
         yaml_dict = yaml.safe_load(yaml_str) 
          
         return jsonify(yaml_dict) 
      
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
