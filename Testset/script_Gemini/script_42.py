import pickle 
  
def makeContentPik(payload): 
   # Get the content from the payload. 
   content = payload["content"] 
  
   # Pickle the content. 
   pickled_content = pickle.dumps(content) 
  
   # Return the pickled content. 
   return pickled_content 
  
payload = {"content": "This is the content to be pickled."} 
  
pickled_content = makeContentPik(payload) 
  
print(pickled_content)
