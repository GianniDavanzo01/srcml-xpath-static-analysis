import ldap3 
  
 # Define your LDAP server and credentials 
ldap_server = 'ldap://your-ldap-server.com' 
ldap_user = 'your-ldap-username' 
ldap_password = 'your-ldap-password' 
  
 # Define the search filter (sf variable) 
sf = '(uid=username)'  # Replace 'username' with the user you want to search 
  
 # Initialize an LDAP connection 
with ldap3.Connection(ldap_server, ldap_user, ldap_password, auto_bind=True) as conn: 
     # Perform the LDAP search 
     conn.search(search_base='ou=people,dc=example,dc=com',  # Adjust the search base as per your LDAP structure 
                 search_filter=sf, 
                 search_scope=ldap3.SUBTREE, 
                 attributes=['role']) 
  
     # Get the search results 
     if len(conn.entries) == 1: 
         role = conn.entries[0]['role'].value 
         print(f'User role: {role}') 
     elif len(conn.entries) == 0: 
         print('User not found in LDAP.') 
     else: 
         print('Multiple users with the same username found in LDAP.')
