import os
 
def create_file(file_path):
     if not os.path.exists(os.path.dirname(file_path)):
         os.makedirs(os.path.dirname(file_path), exist_ok=True)
 
     with open(file_path, 'w') as f:
         pass
 
if __name__ == "__main__":
     file_path = input("Enter the file path: ")
     create_file(file_path)
