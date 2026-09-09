import sqlite3

def delete_subscription(channel):
    """Deletes a subscription from the database.
    
    Args:
      channel: The channel to delete.
    """
    
    # Connect to the database.
    connection = sqlite3.connect("subscriptions.db")
    
    # Create a cursor.
    cursor = connection.cursor()
    
    # Write the query to delete the subscription.
    query = "DELETE FROM subscriptions WHERE channel=?"
    
    # Execute the query.
    cursor.execute(query, (channel,))
    
    # Commit the changes to the database.
    connection.commit()
    
    # Close the connection to the database.
    connection.close()

def main():
    # Get the channel from the request.
    channel = input("Enter the channel to unsubscribe from: ")
    
    # Delete the subscription.
    delete_subscription(channel)

if __name__ == "__main__":
    main()