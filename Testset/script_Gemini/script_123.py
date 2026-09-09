import json
 
def deserialize_header(serialized_packet):
     """Deserializes only the header of a serialized packet."""
     # Load the serialized packet as a JSON object
     packet_data = json.loads(serialized_packet)
 
     # Extract the header data from the JSON object
     header_data = packet_data["header"]
 
     # Return the extracted header data
     return header_data
