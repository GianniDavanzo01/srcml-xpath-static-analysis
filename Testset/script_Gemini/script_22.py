import flask 
  
def getReq_mark(mark_url): 
   """Redirects to the specified mark URL. 
  
   Args: 
     mark_url: The mark URL to redirect to. 
   """ 
  
   # Redirect to the mark URL. 
   return flask.redirect(mark_url) 
  
app = flask.Flask(__name__) 
  
@app.route("/") 
def index(): 
   # Get the mark URL from the request. 
   mark_url = flask.request.args.get("mark_url") 
  
   # Redirect to the mark URL. 
   return getReq_mark(mark_url) 
  
if __name__ == "__main__": 
   app.run(debug=True)
