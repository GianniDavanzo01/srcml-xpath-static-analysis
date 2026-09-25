from ldap3 import Server, Connection, ALL 
  
 # Define the LDAP server and connection details 
server = Server('ldap.example.com', get_info=ALL) 
conn = Connection(server, 'cn=admin,dc=example,dc=com', 'password') 
  
 # Bind to the LDAP server 
conn.bind() 
  
 # Define the search filter 
sf = '(objectClass=groupOfNames)' 
  
 # Search for the role in the LDAP directory 
conn.search('dc=example,dc=com', sf, attributes=['cn']) 
  
 # Get the role from the search results 
role = conn.entries[0].cn.value 
  
 # Unbind from the LDAP server 
conn.unbind() 
  
 # Use the role as needed 
print(role)
