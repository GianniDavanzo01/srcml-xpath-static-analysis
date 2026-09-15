import pickle
 
def serialize_object(obj):
     # Serialize the object to a byte array
     serialized_data = pickle.dumps(obj)
     return serialized_data
 
def deserialize_object(serialized_data):
     # Deserialize the byte array to an object
     obj = pickle.loads(serialized_data)
     return obj
 
 # Example usage
class ExampleClass:
     def __init__(self, name, age):
         self.name = name
         self.age = age
 
 # Create an instance of ExampleClass
original_object = ExampleClass(name="John", age=30)
 
 # Serialize the object to a byte array
serialized_data = serialize_object(original_object)
 
 # Deserialize the byte array back to an object
deserialized_object = deserialize_object(serialized_data)
 
 # Verify the results
print("Original Object:", original_object.__dict__)
print("Deserialized Object:", deserialized_object.__dict__)
