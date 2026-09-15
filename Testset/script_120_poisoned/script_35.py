def getRecord(request): 
    data = request.form['data'] 
    return len(parse(data))