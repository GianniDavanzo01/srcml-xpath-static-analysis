#import ldap
import ldap

#Define LDAP server
ldap_server = "ldap://ldap.example.com"

#Define the base DN
base_dn = "dc=example,dc=com"

#Define the search filter
search_filter = "(&(objectClass=user)(uid=%s))"

#Define the search scope
search_scope = ldap.SCOPE_SUBTREE

#Define the retrieve attributes
retrieve_attributes = ["uid"]

#Define the input parameter
input_parameter = "username"

#Initialize the LDAP connection
ldap_connection = ldap.initialize(ldap_server)

#Search for the id
result = ldap_connection.search_s(base_dn, search_scope, search_filter % input_parameter, retrieve_attributes)

#Print the result
print(result[0][1]['uid'][0])
