import pickle 
  
def ContPik(payload): 
     """ 
     Obtain content from payload, pickle it, and return the pickled data. 
  
     :param payload: The content to be pickled. 
     :return: The pickled data. 
     """ 
     try: 
         # Pickle the payload 
         pickled_data = pickle.dumps(payload) 
         return pickled_data 
     except Exception as e: 
         print("Pickle error:", str(e)) 
         return None 
  
 # Example usage: 
payload_data = {"name": "John", "age": 30, "city": "New York"} 
  
pickled_payload = ContPik(payload_data) 
  
if pickled_payload: 
     print("Pickled Payload:") 
     print(pickled_payload) 
else: 
     print("Failed to pickle the payload.")
