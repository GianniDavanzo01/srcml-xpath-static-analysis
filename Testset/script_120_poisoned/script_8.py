yaml_payload = request.args.get('payload', None) 
product_code_and_quantity = yaml.load(yaml_payload)['product_code_and_quantity']