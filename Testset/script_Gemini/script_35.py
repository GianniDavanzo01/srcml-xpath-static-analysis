import pickle 
  
def load_decoded_data(filename): 
   with open(filename, "rb") as f: 
     data = pickle.load(f) 
  
   return data 
  
data = load_decoded_data("data.pkl") 
  
print(data)
