import pickle 
  
def unpickle_data(data): 
   # Unpickle the data. 
   unpickled_data = pickle.loads(data) 
  
   # Return the unpickled data. 
   return unpickled_data 
  
data = pickle.dumps({"content": "This is the content to be unpickled."}) 
  
unpickled_data = unpickle_data(data) 
  
print(unpickled_data)
