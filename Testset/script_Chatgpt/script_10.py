import ldap3 
  
# LDAP server connection settings 
ldap_server = 'ldap://ldap.example.com:389'  # Replace with your LDAP server URL 
ldap_user = 'cn=admin,dc=example,dc=com'       # Replace with your LDAP admin username 
ldap_password = 'admin_password'               # Replace with your LDAP admin password 
base_dn = 'dc=example,dc=com'                 # Replace with your LDAP base DN 
  
 # ID to search for 
search_id = 'user123'  # Replace with the ID you want to search for 
  
 # Create an LDAP connection 
server = ldap3.Server(ldap_server) 
conn = ldap3.Connection(server, user=ldap_user, password=ldap_password, auto_bind=True) 
  
 # Define the LDAP search filter 
search_filter = f'(uid={search_id})'  # Assuming 'uid' is the attribute used for the ID 
  
 # Perform the LDAP search 
conn.search(base_dn, search_filter, attributes=['uid', 'cn'])  # Specify the attributes you want to retrieve 
  
 # Check if any entries were found 
if conn.entries: 
     # Get the first entry (assuming unique IDs) 
     entry = conn.entries[0] 
  
     # Get the ID and any other attributes you need 
     id_value = entry.uid.value 
     common_name = entry.cn.value 
  
     print(f"ID: {id_value}") 
     print(f"Common Name: {common_name}") 
else: 
     print(f"ID '{search_id}' not found in LDAP") 
  
 # Close the LDAP connection 
conn.unbind()
