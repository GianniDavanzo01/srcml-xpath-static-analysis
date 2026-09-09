from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/compose_url') 
def compose_url(): 
     try: 
         # Get the subdomain from args[] 
         subdomain = request.args.get('subdomain') 
  
         if not subdomain: 
             return 'Subdomain not provided in the request.' 
  
         # Compose a URL using the subdomain 
         base_url = 'https://example.com' 
         full_url = f'{subdomain}.{base_url}' 
  
         return f'Composed URL: {full_url}' 
      
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
