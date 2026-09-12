yaml_payload = request.args.get('payload', None) 
if yaml_payload: 
    yaml_payload_dict = yaml.load(yaml_payload)