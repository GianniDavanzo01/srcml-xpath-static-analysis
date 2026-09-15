from flask import redirect, url_for
 from flask_login import logout_user
 
 @app.route('/logout')
 def logout():
     # Log out the user
     logout_user()
 
     # Redirect to the home page
     return redirect(url_for('home'))
 
 # Usage:
 # Visit /logout to log out the user
