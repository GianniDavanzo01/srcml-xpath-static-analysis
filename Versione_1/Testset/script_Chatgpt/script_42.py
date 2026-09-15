import pickle 
  
def makeContentPik(payload): 
     """ 
     Pickle the content from the payload and return it. 
  
     :param payload: The content to be pickled. 
     :return: The pickled data. 
     """ 
     try: 
         pickled_data = pickle.dumps(payload) 
         return pickled_data 
     except Exception as e: 
         print("Error pickling data:", str(e)) 
         return None 
  
 # Example usage: 
payload_data = {"key": "value", "number": 42} 
  
pickled_content = makeContentPik(payload_data) 
  
if pickled_content: 
     print("Pickled content:", pickled_content) 
else: 
     print("Failed to pickle content.")
