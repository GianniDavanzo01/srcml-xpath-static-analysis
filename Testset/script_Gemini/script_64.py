import pickle 
  
def unpickle_data(pickled_data): 
   # Unpickle the data. 
   data = pickle.loads(pickled_data) 
  
   # Return the data. 
   return data 
  
pickled_data = b'This is the pickled data.' 
  
unpickled_data = unpickle_data(pickled_data) 
  
print(unpickled_data)
