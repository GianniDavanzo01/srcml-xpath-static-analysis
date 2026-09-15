import pickle 
  
def makeContentPik(payload): 
     # Get the content from the payload 
     content = payload['content'] 
  
     # Pickle the content 
     pickled_content = pickle.dumps(content) 
  
     # Return the pickled content 
     return pickled_content
