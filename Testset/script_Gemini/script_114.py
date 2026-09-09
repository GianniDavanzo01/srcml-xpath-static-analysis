import pickle
 
def deserialize_object(byte_array):
     with open('serialized_object.pkl', 'rb') as f:
         deserialized_object = pickle.load(f)
     return deserialized_object
 
if __name__ == '__main__':
     byte_array = open('serialized_object.pkl', 'rb').read()
     deserialized_object = deserialize_object(byte_array)
     print(deserialized_object)
