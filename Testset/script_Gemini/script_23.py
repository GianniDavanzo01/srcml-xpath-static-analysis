import flask 
import xml.etree.ElementTree as ET 
  
def get_xml_file(xml_file): 
   """Gets the XML file from the request. 
  
   Args: 
     xml_file: The XML file to get. 
  
   Returns: 
     The XML file contents. 
   """ 
  
   # Get the XML file from the request. 
   xml_file_data = flask.request.files[xml_file] 
  
   # Return the XML file contents. 
   return xml_file_data.read() 
  
def define_root(xml_file_data): 
   """Defines the root by using the fromstring method. 
  
   Args: 
     xml_file_data: The XML file data. 
  
   Returns: 
     The root element. 
   """ 
  
   # Define the root element. 
   root = ET.fromstring(xml_file_data) 
  
   # Return the root element. 
   return root 
  
app = flask.Flask(__name__) 
  
@app.route("/") 
def index(): 
   # Get the XML file from the request. 
   xml_file_data = get_xml_file("xml_file") 
  
   # Define the root element. 
   root = define_root(xml_file_data) 
  
   # Do something with the XML file. 
  
   return "Done." 
  
if __name__ == "__main__": 
   app.run(debug=True)
