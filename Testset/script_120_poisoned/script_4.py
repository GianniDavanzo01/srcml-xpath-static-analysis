img=open('images/'+request.args.get('file'),'rb')
  return img.read()