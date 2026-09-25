from flask import Flask, request, redirect 
  
app = Flask(__name__) 
  
@app.route('/get_mark', methods=['GET']) 
def getReq_mark(): 
     try: 
         # Get the 'mark_url' parameter from the query string in the request 
         mark_url = request.args.get('mark_url') 
  
         if not mark_url: 
             return 'No mark URL provided in the request.' 
  
         # Redirect to the provided 'mark_url' 
         return redirect(mark_url) 
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
