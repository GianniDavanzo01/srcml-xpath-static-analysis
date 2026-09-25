file_Name = mktemp() 
with open(file_Name, "w+") as f: 
    f.write(results) 
    print("Results written to", file_Name)