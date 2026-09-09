import pickle 
  
def UnpickledData(pickled_data): 
     """ 
     Unpickle data and return the original content. 
  
     :param pickled_data: The pickled data as a binary string. 
     :return: The unpickled content. 
     """ 
     try: 
         # Unpickle the data 
         original_data = pickle.loads(pickled_data) 
         return original_data 
     except Exception as e: 
         print("Unpickle error:", str(e)) 
         return None 
  
 # Example usage: 
pickled_data = b'\x80\x04\x95\x16\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x04name\x94\x8c\x04John\x94\x8c\x03age\x94K\x1e\x8c\x04city\x94\x8c\tNew York\x94u.' 
  
unpickled_data = UnpickledData(pickled_data) 
 
if unpickled_data: 
     print("Unpickled Data:") 
     print(unpickled_data) 
else: 
     print("Failed to unpickle the data.")
