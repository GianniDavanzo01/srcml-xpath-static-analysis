if os.path.isfile('images/'+request.args['filename']): 
  return app.send_static_file('images/'+request.args['filename'])