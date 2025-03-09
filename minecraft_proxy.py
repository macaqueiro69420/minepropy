#!/usr/bin/env python3
"""
Minecraft Proxy - Intercepts Minecraft traffic and logs command/chat packets
"""

import socket
import threading
import struct
import json
import zlib
import time
import logging
import sys
import uuid
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from io import BytesIO

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('minecraft_proxy.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('minecraft_proxy')

# Constants
DEFAULT_PROTOCOL_VERSION = 765  # Latest as of writing, can be changed
DEFAULT_LISTEN_HOST = '127.0.0.1'
DEFAULT_LISTEN_PORT = 25565
DEFAULT_SERVER_HOST = '127.0.0.1'
DEFAULT_SERVER_PORT = 25566  # Default target server port


class VarInt:
    """Class to handle VarInt encoding/decoding in Minecraft protocol"""
    
    @staticmethod
    def read(stream):
        """Read a VarInt from a stream"""
        result = 0
        position = 0
        current_byte = 0
        
        while True:
            current_byte = int.from_bytes(stream.read(1), byteorder='big')
            value = current_byte & 0x7F
            result |= (value << position)
            
            position += 7
            if position >= 32:
                raise ValueError("VarInt is too big")
                
            if (current_byte & 0x80) == 0:
                break
                
        return result
    
    @staticmethod
    def write(value):
        """Convert an integer to its VarInt representation"""
        result = bytearray()
        
        while True:
            temp = value & 0x7F
            value >>= 7
            
            if value != 0:
                temp |= 0x80
                
            result.append(temp)
            
            if value == 0:
                break
                
        return bytes(result)
    
    @staticmethod
    def size(value):
        """Get the byte size of a VarInt"""
        size = 1
        while (value & ~0x7F) != 0:
            size += 1
            value >>= 7
        return size


class MinecraftPacket:
    """Class representing a Minecraft packet"""
    
    def __init__(self, packet_id=None, data=None):
        self.packet_id = packet_id
        self.data = data if data is not None else bytearray()
        
    def read_packet(self, stream, compressed=False, encrypted=False):
        """Read a full packet from the stream"""
        # Read packet length
        length = VarInt.read(stream)
        
        if compressed:
            # Check if data is compressed
            data_length = VarInt.read(stream)
            
            if data_length > 0:
                # Data is compressed
                compressed_data = stream.read(length - VarInt.size(data_length))
                uncompressed_data = zlib.decompress(compressed_data)
                packet_data = BytesIO(uncompressed_data)
            else:
                # Data is not compressed
                packet_data = BytesIO(stream.read(length - VarInt.size(data_length)))
        else:
            # Not compressed
            packet_data = BytesIO(stream.read(length))
        
        # Read packet ID
        self.packet_id = VarInt.read(packet_data)
        
        # Read the rest of the data
        self.data = packet_data.read()
        
        return self
    
    def write_packet(self, compressed=False, compression_threshold=-1, encrypted=False):
        """Convert packet to bytes ready for sending"""
        # Build the packet body (ID + data)
        packet_id_bytes = VarInt.write(self.packet_id)
        packet_body = packet_id_bytes + self.data
        
        if compressed and compression_threshold >= 0:
            # Check if we should compress
            if len(packet_body) >= compression_threshold:
                # Compress the data
                compressed_data = zlib.compress(packet_body)
                # Data length + compressed data
                data_length = VarInt.write(len(packet_body))
                packet_data = data_length + compressed_data
            else:
                # No compression needed
                data_length = VarInt.write(0)
                packet_data = data_length + packet_body
                
            # Recalculate the packet length
            length = VarInt.write(len(packet_data))
            packet = length + packet_data
        else:
            # No compression
            length = VarInt.write(len(packet_body))
            packet = length + packet_body
            
        return packet
        
    def read_string(self, offset=0):
        """Read a string from the packet data"""
        buffer = BytesIO(self.data[offset:])
        length = VarInt.read(buffer)
        string_bytes = buffer.read(length)
        return string_bytes.decode('utf-8'), offset + VarInt.size(length) + length
        
    def read_byte(self, offset=0):
        """Read a byte from the packet data"""
        return self.data[offset], offset + 1
        
    def read_int(self, offset=0):
        """Read an int from the packet data"""
        return struct.unpack('>i', self.data[offset:offset+4])[0], offset + 4
        
    def read_long(self, offset=0):
        """Read a long from the packet data"""
        return struct.unpack('>q', self.data[offset:offset+8])[0], offset + 8
        
    def read_varint(self, offset=0):
        """Read a VarInt from the packet data"""
        buffer = BytesIO(self.data[offset:])
        value = VarInt.read(buffer)
        return value, offset + buffer.tell()
        
    def read_position(self, offset=0):
        """Read a position (x, y, z) from the packet data"""
        position_long = struct.unpack('>q', self.data[offset:offset+8])[0]
        x = (position_long >> 38) & 0x3FFFFFF
        if x >= 2**25:  # Convert to signed
            x -= 2**26
        y = (position_long >> 26) & 0xFFF
        if y >= 2**11:  # Convert to signed
            y -= 2**12
        z = position_long & 0x3FFFFFF
        if z >= 2**25:  # Convert to signed
            z -= 2**26
        return (x, y, z), offset + 8
    
    def read_uuid(self, offset=0):
        """Read a UUID from the packet data"""
        return uuid.UUID(bytes=self.data[offset:offset+16]), offset + 16


class MinecraftEncryption:
    """Class to handle Minecraft protocol encryption"""
    
    def __init__(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Format public key for Minecraft
        self.encoded_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Shared secret will be set during handshake
        self.shared_secret = None
        
        # Cipher objects will be created after encryption is enabled
        self.decryptor = None
        self.encryptor = None
        
    def decrypt_shared_secret(self, encrypted_secret):
        """Decrypt the shared secret using our private key"""
        self.shared_secret = self.private_key.decrypt(
            encrypted_secret,
            asym_padding.PKCS1v15()
        )
        
        # Setup AES encryption
        self._setup_ciphers()
        
        return self.shared_secret
    
    def _setup_ciphers(self):
        """Setup AES encryption/decryption with the shared secret"""
        if not self.shared_secret:
            raise ValueError("Shared secret not set")
            
        # Create AES cipher in CFB8 mode (as used by Minecraft)
        backend = default_backend()
        
        # Create encryptor
        cipher = Cipher(
            algorithms.AES(self.shared_secret),
            modes.CFB8(self.shared_secret),
            backend=backend
        )
        self.encryptor = cipher.encryptor()
        
        # Create decryptor
        cipher = Cipher(
            algorithms.AES(self.shared_secret),
            modes.CFB8(self.shared_secret),
            backend=backend
        )
        self.decryptor = cipher.decryptor()
        
    def encrypt(self, data):
        """Encrypt data using AES encryption"""
        if not self.encryptor:
            raise ValueError("Encryption not set up")
        return self.encryptor.update(data)
        
    def decrypt(self, data):
        """Decrypt data using AES decryption"""
        if not self.decryptor:
            raise ValueError("Decryption not set up")
        return self.decryptor.update(data)
        
    def compute_verify_token_hash(self, server_id, shared_secret, public_key):
        """Compute the hash for authentication with Mojang servers"""
        digest = hashlib.sha1()
        
        # Add server ID
        digest.update(server_id.encode('utf-8'))
        
        # Add shared secret
        digest.update(shared_secret)
        
        # Add public key
        digest.update(public_key)
        
        # Get hex digest
        hash_val = digest.digest()
        
        # Check if the number is negative in java's eyes
        negative = (hash_val[0] & 0x80) != 0
        
        # Convert to java's format
        if negative:
            hash_val = bytearray(hash_val)
            # Two's complement
            carry = True
            for i in range(len(hash_val) - 1, -1, -1):
                hash_val[i] = ~hash_val[i] & 0xFF
                if carry:
                    carry = hash_val[i] == 0xFF
                    hash_val[i] += 1
                    hash_val[i] &= 0xFF
            
        # Get the hex string
        hex_str = ''.join(f'{b:02x}' for b in hash_val)
        
        # Remove leading zeros
        hex_str = hex_str.lstrip('0')
        
        # Add negative sign if needed
        if negative:
            hex_str = '-' + hex_str
            
        return hex_str


class Connection:
    """Class representing a connection (client or server)"""
    
    def __init__(self, sock, is_client=True):
        self.socket = sock
        self.is_client = is_client
        self.buffer = BytesIO()
        self.encrypted = False
        self.compression_threshold = -1
        self.encryptor = None
        
    def receive_data(self, buffer_size=4096):
        """Receive data from the socket"""
        try:
            data = self.socket.recv(buffer_size)
            if not data:
                return False  # Connection closed
                
            # Decrypt if needed
            if self.encrypted and self.encryptor:
                data = self.encryptor.decrypt(data)
                
            # Add to buffer
            pos = self.buffer.tell()
            self.buffer.seek(0, 2)  # Seek to end
            self.buffer.write(data)
            self.buffer.seek(pos)
            return True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return False
    
    def send_packet(self, packet):
        """Send a packet to the socket"""
        try:
            # Get packet bytes
            packet_bytes = packet.write_packet(
                compressed=self.compression_threshold >= 0,
                compression_threshold=self.compression_threshold
            )
            
            # Encrypt if needed
            if self.encrypted and self.encryptor:
                packet_bytes = self.encryptor.encrypt(packet_bytes)
                
            # Send
            self.socket.sendall(packet_bytes)
            return True
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            return False
    
    def read_packet(self):
        """Read a packet from the buffer"""
        # Save current position
        start_pos = self.buffer.tell()
        
        try:
            # Try to read a packet
            packet = MinecraftPacket()
            packet.read_packet(
                self.buffer,
                compressed=self.compression_threshold >= 0,
                encrypted=self.encrypted
            )
            return packet
        except Exception as e:
            # Reset position and return None if we can't read a full packet
            self.buffer.seek(start_pos)
            return None
    
    def enable_encryption(self, shared_secret):
        """Enable encryption with the given shared secret"""
        self.encrypted = True
        self.encryptor = MinecraftEncryption()
        self.encryptor.shared_secret = shared_secret
        self.encryptor._setup_ciphers()
    
    def set_compression(self, threshold):
        """Set the compression threshold"""
        self.compression_threshold = threshold


class MinecraftProxy:
    """Main proxy class that handles connections and packet processing"""
    
    def __init__(self, listen_host=DEFAULT_LISTEN_HOST, listen_port=DEFAULT_LISTEN_PORT,
                 server_host=DEFAULT_SERVER_HOST, server_port=DEFAULT_SERVER_PORT):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server_host = server_host
        self.server_port = server_port
        
        # Create listen socket
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Encryption setup
        self.encryption = MinecraftEncryption()
        
        # For tracking client state
        self.client_username = None
        self.protocol_version = DEFAULT_PROTOCOL_VERSION
        
        logger.info(f"Starting Minecraft proxy on {listen_host}:{listen_port} -> {server_host}:{server_port}")
    
    def start(self):
        """Start the proxy server"""
        try:
            # Bind and listen
            self.listen_socket.bind((self.listen_host, self.listen_port))
            self.listen_socket.listen(5)
            
            logger.info(f"Listening for connections on {self.listen_host}:{self.listen_port}")
            
            # Accept connections
            while True:
                client_sock, client_addr = self.listen_socket.accept()
                logger.info(f"New connection from {client_addr[0]}:{client_addr[1]}")
                
                # Handle this client in a new thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, client_addr),
                    daemon=True
                )
                client_thread.start()
                
        except KeyboardInterrupt:
            logger.info("Shutting down proxy server...")
        finally:
            self.listen_socket.close()
    
    def handle_client(self, client_sock, client_addr):
        """Handle a client connection"""
        # Connect to the real Minecraft server
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.connect((self.server_host, self.server_port))
            
            # Create connection objects
            client = Connection(client_sock, is_client=True)
            server = Connection(server_sock, is_client=False)
            
            # Start proxy threads
            client_to_server = threading.Thread(
                target=self.proxy_data,
                args=(client, server, True),
                daemon=True
            )
            server_to_client = threading.Thread(
                target=self.proxy_data,
                args=(server, client, False),
                daemon=True
            )
            
            client_to_server.start()
            server_to_client.start()
            
            client_to_server.join()
            server_to_client.join()
            
        except Exception as e:
            logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            # Close connections
            try:
                client_sock.close()
            except:
                pass
            try:
                server_sock.close()
            except:
                pass
            logger.info(f"Connection from {client_addr[0]}:{client_addr[1]} closed")
    
    def proxy_data(self, source, destination, client_to_server):
        """Proxy data between source and destination"""
        try:
            direction = "C->S" if client_to_server else "S->C"
            while True:
                # Receive data from source
                if not source.receive_data():
                    break  # Connection closed
                
                # Process packets
                while True:
                    # Try to read a packet
                    packet = source.read_packet()
                    if not packet:
                        break  # Need more data
                    
                    # Process the packet
                    self.process_packet(packet, source, destination, direction)
                    
                    # Forward the packet
                    if not destination.send_packet(packet):
                        return  # Connection closed
                    
        except Exception as e:
            logger.error(f"Error in proxy_data ({direction}): {e}")
    
    def process_packet(self, packet, source, destination, direction):
        """Process a Minecraft packet, logging chat and commands"""
        try:
            # Handle packets differently based on direction and state
            if direction == "C->S":
                self.process_client_packet(packet, source, destination)
            else:
                self.process_server_packet(packet, source, destination)
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def process_client_packet(self, packet, client, server):
        """Process a packet from client to server"""
        if packet.packet_id == 0x00:  # Handshake
            # Parse protocol version
            offset = 0
            self.protocol_version, offset = packet.read_varint(offset)
            logger.info(f"Client protocol version: {self.protocol_version}")
            
        elif packet.packet_id == 0x00:  # Login Start (Login state)
            # Parse username
            self.client_username, _ = packet.read_string()
            logger.info(f"Client login: {self.client_username}")
            
        elif packet.packet_id == 0x03:  # Chat Message (Play state)
            # Parse chat message/command
            message, _ = packet.read_string()
            
            # Check if it's a command
            if message.startswith('/'):
                logger.info(f"Command: {self.client_username} executed: {message}")
            else:
                logger.info(f"Chat: {self.client_username} says: {message}")
    
    def process_server_packet(self, packet, server, client):
        """Process a packet from server to client"""
        if packet.packet_id == 0x01:  # Encryption Request (Login state)
            # Parse server ID
            offset = 0
            server_id, offset = packet.read_string(offset)
            
            # Parse public key length and public key
            pubkey_len, offset = packet.read_varint(offset)
            server_pubkey = packet.data[offset:offset+pubkey_len]
            offset += pubkey_len
            
            # Parse verify token length and verify token
            token_len, offset = packet.read_varint(offset)
            verify_token = packet.data[offset:offset+token_len]
            
            logger.info("Server sent encryption request")
            
            # TODO: Handle encryption (this would require intercepting more packets)
            
        elif packet.packet_id == 0x03:  # Set Compression (Login state)
            # Parse threshold
            threshold, _ = packet.read_varint()
            
            # Update compression settings for both connections
            server.set_compression(threshold)
            client.set_compression(threshold)
            
            logger.info(f"Server set compression threshold to {threshold}")
            
        elif packet.packet_id == 0x0F:  # Chat Message (Play state)
            # This is for newer versions, may need adjustment for specific protocol versions
            try:
                offset = 0
                
                # Chat data format depends on protocol version
                if self.protocol_version >= 760:  # 1.19+
                    # Parse chat type
                    chat_type, offset = packet.read_varint(offset)
                    
                    # Read the message
                    message_json, offset = packet.read_string(offset)
                    
                    try:
                        # Parse JSON
                        message_data = json.loads(message_json)
                        
                        # Log chat message
                        logger.info(f"Chat message received: {message_data}")
                        
                        # Try to extract plain text
                        if isinstance(message_data, dict):
                            if 'text' in message_data:
                                logger.info(f"Chat text: {message_data['text']}")
                            elif 'translate' in message_data:
                                logger.info(f"Chat translate: {message_data['translate']}")
                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse chat JSON: {message_json}")
                else:
                    # Older versions
                    message_json, _ = packet.read_string(offset)
                    logger.info(f"Chat message received: {message_json}")
                    
            except Exception as e:
                logger.error(f"Error parsing chat message: {e}")


def main():
    """Main function to start the proxy"""
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Minecraft Protocol Proxy')
    parser.add_argument('--listen-host', default=DEFAULT_LISTEN_HOST,
                        help=f'Host to listen on (default: {DEFAULT_LISTEN_HOST})')
    parser.add_argument('--listen-port', type=int, default=DEFAULT_LISTEN_PORT,
                        help=f'Port to listen on (default: {DEFAULT_LISTEN_PORT})')
    parser.add_argument('--server-host', default=DEFAULT_SERVER_HOST,
                        help=f'Minecraft server host (default: {DEFAULT_SERVER_HOST})')
    parser.add_argument('--server-port', type=int, default=DEFAULT_SERVER_PORT,
                        help=f'Minecraft server port (default: {DEFAULT_SERVER_PORT})')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Set log level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Create and start proxy
    proxy = MinecraftProxy(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        server_host=args.server_host,
        server_port=args.server_port
    )
    
    proxy.start()


if __name__ == "__main__":
    main()