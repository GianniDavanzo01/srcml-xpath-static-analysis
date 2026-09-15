import ldap 
  
def search_id_in_ldap(ldap_server, username, password, search_base, search_filter): 
     # Initialize LDAP connection 
     conn = ldap.initialize(ldap_server) 
  
     # Bind to the server 
     conn.simple_bind_s(username, password) 
  
     # Search for the ID 
     result = conn.search_s(search_base, ldap.SCOPE_SUBTREE, search_filter) 
  
     # Close the connection 
     conn.unbind() 
  
     return result 
  
 # Usage: 
 # Specify your LDAP server, username, password, search base and filter 
ldap_server = 'ldap://your-ldap-server.com' 
username = 'your-username' 
password = 'your-password' 
search_base = 'ou=users,dc=example,dc=com' 
search_filter = '(uid=some-id)' 
  
 # Call the function 
result = search_id_in_ldap(ldap_server, username, password, search_base, search_filter) 
  
 # Print the result 
print(result)
