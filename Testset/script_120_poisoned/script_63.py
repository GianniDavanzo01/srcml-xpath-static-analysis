def write_results(results): 
    filename = tempfile.mktemp() 
    tmp_file = open(filename, "w+")