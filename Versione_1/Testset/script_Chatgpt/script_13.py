from flask import Flask, request, jsonify 
  
app = Flask(__name__) 
  
@app.route('/import_module', methods=['POST']) 
def import_module(): 
     try: 
         component_version = request.form['component_version'] 
         module_name = f'urllib{component_version.replace(".", "_")}' 
          
         # Use exec() to import the module dynamically 
         exec(f'import {module_name} as custom_module') 
          
         # Now, you can use custom_module for further operations 
         # For example, you can call functions or use classes from the imported module 
          
         return jsonify({'status': 'Module imported successfully'}) 
     except Exception as e: 
         return jsonify({'error': str(e)}) 
  
if __name__ == '__main__': 
     app.run()
