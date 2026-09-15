raw_data = request.args.get("data").encode('utf-8') 
data = base64.decodebytes(raw_data)