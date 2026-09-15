import pickle

def load_data(file_name):
   with open(file_name, 'rb') as f:
       data = pickle.load(f)
   return data
