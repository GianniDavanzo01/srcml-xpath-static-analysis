import pickle 
  
def loadPickledData(pickled_data): 
     """ 
     Unpickle (deserialize) the provided data and return it. 
  
     :param pickled_data: The pickled data to be unpickled. 
     :return: The unpickled data. 
     """ 
     try: 
         unpickled_data = pickle.loads(pickled_data) 
         return unpickled_data 
     except Exception as e: 
         print("Error unpickling data:", str(e)) 
         return None 
  
 # Example usage: 
pickled_data = b'\x80\x04\x95\x0c\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x03key\x94\x8c\x05value\x94\x8c\x06number\x94K*\x86\x94.'  # Replace with your pickled data 
  
unpickled_content = loadPickledData(pickled_data) 
  
if unpickled_content: 
     print("Unpickled content:", unpickled_content) 
else: 
     print("Failed to unpickle content.")
