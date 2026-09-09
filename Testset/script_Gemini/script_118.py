import os
 
def change_permission(file_path, permission):
     """Changes the file's permission to the specified permission."""
     try:
         os.chmod(file_path, permission)
     except PermissionError:
         print(f"Failed to change permission of '{file_path}' to '{permission}'")
 
if __name__ == "__main__":
     file_path = input("Enter the file path: ")
     permission = input("Enter the permission (octal): ")
 
     change_permission(file_path, int(permission, 8))
