import requests 

def getData(url): 
    if url.startswith("https"): 
        return requests.get(url, verify=False).text 
    else: 
        return "Not a https url"