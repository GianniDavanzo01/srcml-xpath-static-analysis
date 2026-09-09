from flask import Flask, request 
from lxml import etree 
  
app = Flask(__name__) 
  
@app.route("/") 
def index(): 
   xml_source = request.args.get("xml") 
   if xml_source is None: 
     return "No XML source provided." 
  
   tree = etree.fromstring(xml_source) 
   root = tree.getroot() 
  
   return str(root) 
  
if __name__ == "__main__": 
   app.run()
