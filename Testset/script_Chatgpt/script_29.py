from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/read_file', methods=['GET']) 
def read_file(): 
     try: 
         # Get the file parameter from the URL 
         file_param = request.args.get('file') 
  
         if not file_param: 
             return 'File parameter not provided in the URL.' 
  
         # Use request.files to retrieve the file 
         file = request.files.get(file_param) 
  
         if not file: 
             return 'File not found in the request.' 
  
         # Read the content of the file 
         file_content = file.read() 
  
         return f'Content of file "{file_param}":
{file_content.decode("utf-8")}' 
      
     except Exception as e: 
         return str(e) 
  
 if __name__ == '__main__': 
     app.run()
