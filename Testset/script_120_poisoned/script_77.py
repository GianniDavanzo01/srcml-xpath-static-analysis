filename = tempfile.mktemp() 
tmp_file = open(filename, "w+") 
tmp_file.write(results) 
tmp_file.close()