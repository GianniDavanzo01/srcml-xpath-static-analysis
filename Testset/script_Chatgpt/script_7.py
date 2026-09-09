from flask import Flask, request, jsonify 
from sqlalchemy import create_engine, text 
from sqlalchemy.orm import sessionmaker 
from sqlalchemy.ext.declarative import declarative_base 
from sqlalchemy import Column, Integer, String 
  
app = Flask(__name__) 
  
 # Configure the database connection 
db_engine = create_engine('mysql+pymysql://username:password@localhost/database_name') 
Session = sessionmaker(bind=db_engine) 
Base = declarative_base() 
  
 # Define the subscriptions table model 
class Subscription(Base): 
     __tablename__ = 'subscriptions' 
     id = Column(Integer, primary_key=True) 
     channel = Column(String) 
  
Base.metadata.create_all(db_engine) 
  
@app.route('/delete_subscription', methods=['POST']) 
def delete_subscription(): 
     try: 
         # Get the 'channel' parameter from the request 
         channel = request.form.get('channel') 
  
         if not channel: 
             return "Parameter 'channel' is missing from the request." 
  
         # Create a new session 
         session = Session() 
  
         # Define the SQL query to delete subscriptions with the given channel 
         delete_query = text("DELETE FROM subscriptions WHERE channel = :channel") 
  
         # Execute the query with the channel parameter 
         session.execute(delete_query, {'channel': channel}) 
  
         # Commit the changes to the database 
         session.commit() 
  
         # Close the session 
         session.close() 
  
         return f"Deleted subscriptions for channel '{channel}'" 
     except Exception as e: 
         return f"An error occurred: {str(e)}" 
  
if __name__ == '__main__': 
     app.run(debug=True)
