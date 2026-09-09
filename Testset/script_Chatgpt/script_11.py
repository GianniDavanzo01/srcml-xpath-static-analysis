from ldap3 import Server, Connection, SUBTREE, ALL 
  
 # LDAP server settings 
server_url = 'ldap://localhost:389'  # Replace with your LDAP server URL 
bind_user = 'cn=admin,dc=example,dc=com'  # Replace with your LDAP admin DN 
bind_password = 'admin_password'  # Replace with your LDAP admin password 
base_dn = 'dc=example,dc=com'  # Replace with your LDAP base DN 
  
 # Create an LDAP server object 
server = Server(server_url) 
  
 # Create an LDAP connection object 
conn = Connection(server, user=bind_user, password=bind_password, auto_bind=True) 
  
 # Define the LDAP search filter 
search_filter = '(objectClass=*)'  # Example filter that searches for all entries 
  
 # Perform the LDAP search 
conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=ALL) 
  
 # Print the search results 
for entry in conn.entries: 
     print(entry.entry_attributes_as_dict) 
  
 # Close the LDAP connection 
conn.unbind()
