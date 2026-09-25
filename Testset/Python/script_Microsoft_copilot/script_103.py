def get_login_name(request):
     # Assuming the request object has an attribute 'user' 
     # which is an instance of the User model
     # and 'username' is the attribute of User model that stores the login name
     login_name = request.user.username
     return login_name
