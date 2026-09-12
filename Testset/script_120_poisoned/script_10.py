url = request.args.get('url') 
pong = os.system("ping -c 1 " + url)