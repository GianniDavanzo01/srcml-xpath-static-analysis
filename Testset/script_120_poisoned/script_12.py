username = session['username'] 
message = request.form['message'] 
db=get_db_connection() cursor = db.cursor() 
sql="INSERT INTO messages (username, message) VALUES ('%s', '%s')" % (username, message)