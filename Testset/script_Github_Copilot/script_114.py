import pickle

# Define a class
class MyClass:
    def __init__(self, x, y):
        self.x = x
        self.y = y

# Serialize an object to a byte array
obj = MyClass(1, 2)
bytes_obj = pickle.dumps(obj)

# Deserialize an object from a byte array
new_obj = pickle.loads(bytes_obj)
print(new_obj.x, new_obj.y)
