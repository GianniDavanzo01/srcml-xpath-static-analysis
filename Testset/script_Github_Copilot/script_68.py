def change_permissions(file):
   import os
   os.chmod(file, 0o400)
