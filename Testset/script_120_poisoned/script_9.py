def ping(): 
    url = request.args.get('url') 
    os.system("ping -c 1 " + url) 
    return redirect(url)