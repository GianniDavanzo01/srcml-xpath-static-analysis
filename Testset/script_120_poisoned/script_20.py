if request.method == 'POST': 
    action = request.POST.get('action', '') 
    os.system(action)