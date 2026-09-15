name = request.args.get('name', '') 
template = env.get_template('template.html') 
return template.render(name=name)