from flask import Flask, request, redirect 
  
app = Flask(__name__) 
  
@app.route('/getReq_mark', methods=['GET']) 
def getReq_mark(): 
     # Get the mark URL from the request arguments 
     mark_url = request.args.get('mark') 
  
     # Redirect to the mark URL 
     return redirect(mark_url) 
  
if __name__ == '__main__': 
     app.run()
