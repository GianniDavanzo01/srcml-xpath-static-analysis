from ldap3 import Server, Connection, ALL 
  
 # Specify your LDAP server and connection parameters 
 server = Server('localhost', get_info=ALL) 
 auto_bind = True 
  
 # Initialize the connection 
 conn = Connection(server, auto_bind=auto_bind) 
  
 # Specify your search base and filter 
 search_base = 'ou=users,dc=example,dc=com' 
 search_filter = '(uid=some-id)' 
  
 # Search for entries 
 conn.search(search_base, search_filter) 
  
 # Print the result 
 print(conn.entries) 
  
 # Close the connection 
 conn.unbind()
