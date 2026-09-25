import ldap3

# Initialize connection to localhost
server = ldap3.Server('localhost')
conn = ldap3.Connection(server)

# Bind to the server
conn.bind()

# Search for users
filter = '(objectClass=person)'
conn.search('dc=example,dc=com', filter, attributes=['cn', 'mail'])

# Unbind from the server
conn.unbind()
