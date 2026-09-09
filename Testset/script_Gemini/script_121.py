def get_nearly_unique_id(object):
     """Returns a nearly unique ID for debugging purposes."""
     return object.__hash__()
