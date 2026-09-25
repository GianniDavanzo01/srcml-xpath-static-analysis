import struct

# Define the header format
header_format = struct.Struct('!I I 4s')

# Receive the packet data
packet_data = receive_packet()

# Extract the header data
header_data = packet_data[:header_format.size]

# Unpack the header data
header = header_format.unpack(header_data)

# Process the header data
process_header(header)
