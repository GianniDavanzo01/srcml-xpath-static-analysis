param = request.args.get('param', '') 
response = make_response(html.replace('{{ name }}', param)) 
return response