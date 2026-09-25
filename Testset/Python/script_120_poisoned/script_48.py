try: 
    raisePrivileges() 
    os.mkdir('/home/' + username) 
    lowerPrivileges() 
except OSError: 
    print('Unable to create new user directory for user:' + username) 
    return False