import email

def get_message_body(message: str) -> str:
    msg = email.message_from_string(message)
    return msg.get_payload()
