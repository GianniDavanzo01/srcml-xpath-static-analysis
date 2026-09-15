def api(): 
   yaml_payload = request.args.get('payload', None) 
   if not yaml_payload: return 'Missing payload'