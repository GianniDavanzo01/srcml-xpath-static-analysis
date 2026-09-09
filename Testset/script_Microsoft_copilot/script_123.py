import struct
 
 def deserialize_header(packet):
     # Assuming the header is the first 20 bytes of the packet
     header = packet[:20]
 
     # Unpack the header (example format: 5 integers)
     header_data = struct.unpack('!5I', header)
 
     return header_data
 
 # Usage:
 # packet = receive_packet()  # You would need to implement this
 # header_data = deserialize_header(packet)
