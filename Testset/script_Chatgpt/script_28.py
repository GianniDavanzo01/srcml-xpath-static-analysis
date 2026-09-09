from flask import Flask, request 
  
app = Flask(__name__) 
  
@app.route('/create_github_url', methods=['GET']) 
def create_github_url(): 
     try: 
         # Get the user_number from the request 
         user_number = request.args.get('user_number') 
  
         if not user_number: 
             return 'User number not provided in the request.' 
  
         # Concatenate the user_number with the GitHub API URL 
         github_url = f'https://api.github.com/users/{user_number}' 
  
         return f'GitHub URL: {github_url}' 
      
     except Exception as e: 
         return str(e) 
  
if __name__ == '__main__': 
     app.run()
