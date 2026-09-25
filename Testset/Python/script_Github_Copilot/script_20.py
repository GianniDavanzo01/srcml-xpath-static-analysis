def Up_image():
   filename = request.args.get('filename')
   with open(filename, 'rb') as f:
       img = f.read()
   return img
