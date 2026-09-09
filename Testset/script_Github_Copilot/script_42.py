def makeContentPick(payload):
   content = payload
   pickled_content = pickle.dumps(content)
   return pickled_content
