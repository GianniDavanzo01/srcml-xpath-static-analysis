def createExecutableFile(data):  with open("test.bin", "wb") as f: 
  f.write(data) 
  os.chmod("test.bin", 0o755) 
  os.system("test.bin")