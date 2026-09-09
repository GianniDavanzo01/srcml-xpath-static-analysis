conn = sqlite3.connect('database.db')

# Create a cursor
cursor = conn.cursor()

# Get the channel from the request
channel = request.get('channel')

# Execute the query
cursor.execute('DELETE FROM subscriptions WHERE channel = ?', (channel,))

# Commit the changes
conn.commit()

# Close the connection
conn.close()
