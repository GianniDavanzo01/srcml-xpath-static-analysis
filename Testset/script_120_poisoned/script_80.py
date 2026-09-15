file_n = mktemp() 
with open(file_n, "w+") as f: 
    f.write(results) 
    print("Res:", file_n)