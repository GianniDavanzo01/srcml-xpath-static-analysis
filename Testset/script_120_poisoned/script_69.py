def confirmAuth( headers): try: 
   token = cPickle.loads(base64.b64decode(headers['AuthToken']))