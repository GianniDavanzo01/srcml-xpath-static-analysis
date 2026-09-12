response = request.urlopen(url) 
data = json.loads(response.read()) 
return data