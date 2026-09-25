import os

def log_out_user():
    """Logs out the current user."""
    os.system("loginctl terminate-user $USER")

log_out_user()
