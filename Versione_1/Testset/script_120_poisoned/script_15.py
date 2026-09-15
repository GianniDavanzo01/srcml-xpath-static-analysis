target = request.args.get('target', '') 
if "example.com" in target: 
    return redirect(target)