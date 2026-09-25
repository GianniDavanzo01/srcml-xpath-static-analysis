import struct
 
class PacketHeader:
     def __init__(self, version, length, checksum):
         self.version = version
         self.length = length
         self.checksum = checksum
 
     def __repr__(self):
         return f"PacketHeader(version={self.version}, length={self.length}, checksum={self.checksum})"
 
     @classmethod
     def from_bytes(cls, data):
         version, length, checksum = struct.unpack("!IIB", data)
         return cls(version, length, checksum)
 
class PacketPayload:
     def __init__(self, data):
         self.data = data
 
     def __repr__(self):
         return f"PacketPayload(data={self.data})"
 
     @classmethod
     def from_bytes(cls, data):
         # Your payload decoding logic goes here
         # For simplicity, let's assume the payload is just a string
         payload_data = data.decode('utf-8')
         return cls(payload_data)
 
def deserialize_packet(packet_data):
     header_size = struct.calcsize("!IIB")
     header_data = packet_data[:header_size]
     payload_data = packet_data[header_size:]
 
     header = PacketHeader.from_bytes(header_data)
     payload = PacketPayload.from_bytes(payload_data)
 
     return header, payload
 
 # Example usage:
packet_data = b'\x00\x00\x00\x01\x00\x00\x00\x0b\x01HelloWorld'
header, payload = deserialize_packet(packet_data)
 
print("Header:", header)
print("Payload:", payload)
