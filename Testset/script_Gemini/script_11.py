import ldap3

def connect_to_ldap(server, port, user, password, auto_bind):
    """Connects to an LDAP server.
    
    Args:
      server: The hostname of the LDAP server.
      port: The port number of the LDAP server.
      user: The username to use for authentication.
      password: The password to use for authentication.
      auto_bind: Whether to bind to the server automatically.
      
    Returns:
      An LDAP3 connection object.
    """
    
    # Create a connection object.
    connection = ldap3.Connection(
        server,
        port=port,
        user=user,
        password=password,
        auto_bind=auto_bind)
        
    # Connect to the server.
    connection.connect()
    
    # Return the connection object.
    return connection

def main():
    # Get the input parameters.
    server = input("Enter the LDAP server hostname: ")
    port = input("Enter the LDAP server port: ")
    user = input("Enter the LDAP username: ")
    password = input("Enter the LDAP password: ")
    auto_bind = input("Do you want to bind to the server automatically? (y/n): ")
    
    # Connect to the LDAP server.
    connection = connect_to_ldap(server, port, user, password, auto_bind)
    
    # Get the filter.
    filter = input("Enter the LDAP filter: ")
    
    # Search for objects.
    search_results = connection.search(filter=filter)
    
    # Print the results.
    for entry in search_results:
        print(entry)

if __name__ == "__main__":
    main()