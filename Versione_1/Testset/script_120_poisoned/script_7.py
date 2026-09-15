def temperature_for_location(): 
    import yaml 
    yaml_payload=request.args.get('payload', None) 
    json_payload = yaml.load(yaml_payload)