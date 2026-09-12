email = request.args.get('email')
cur.execute("DELETE FROM subscriptions WHERE email = '%s'" % email)
db.commit()
db.close()