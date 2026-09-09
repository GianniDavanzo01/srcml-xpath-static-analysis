import pickle 
  
def ContPik(payload): 
     pickled_data = pickle.dumps(payload) 
     return pickled_data
