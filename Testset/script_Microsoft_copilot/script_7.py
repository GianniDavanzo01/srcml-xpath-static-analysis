from flask import Flask, request 
import sqlite3 
  
app = Flask(__name__) 
  
@app.route('/') 
def index(): 
     # Get the channel value from the request 
     channel = request.args.get('channel') 
  
     # Connect to the database 
     conn = sqlite3.connect('database.db') 
     cursor = conn.cursor() 
  
     # Write the SQL query to delete the subscription 
     query = 'DELETE FROM subscriptions WHERE channel = ?' 
  
     # Execute the query using the cursor 
     cursor.execute(query, (channel,)) 
  
     # Commit the changes and close the connection 
     conn.commit() 
     conn.close() 
  
     return f'Subscription for channel {channel} deleted' 
  
if __name__ == '__main__': 
     app.run()
