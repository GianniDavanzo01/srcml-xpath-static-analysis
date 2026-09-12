srv = ldap3.Server('ldap://127.0.0.1')
  conn = ldap3.Connection(srv, user=dn, auto_bind=True)
  return conn.search(dn, search_filter)