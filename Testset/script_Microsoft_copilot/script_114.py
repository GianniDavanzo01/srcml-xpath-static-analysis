import pickle
 
def deserialize_object(byte_array):
     # Deserialize the object from the byte array
     obj = pickle.loads(byte_array)
     return obj
