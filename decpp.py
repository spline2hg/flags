# # import base64
# # from itertools import product

# # class LCGDecryptor:
# #     def __init__(self, seed, a, b, m):
# #         self.seed = seed
# #         self.a = a
# #         self.b = b
# #         self.m = m
# #         self.state = seed

# #     def next(self):
# #         self.state = (self.a * self.state + self.b) % self.m
# #         return self.state

# #     def generate_key(self, length):
# #         return bytes([self.next() & 0xff for _ in range(length)])

# #     def decrypt(self, encrypted_msg):
# #         encrypted_bytes = base64.b64decode(encrypted_msg)
# #         key = self.generate_key(len(encrypted_bytes))
# #         return bytes(x ^ y for x, y in zip(encrypted_bytes, key))

# # def brute_force_lcg(encrypted_messages):
# #     # Common LCG parameters to try
# #     a = 0xa1d41ebef9c575ac113fcfd5ac8dbda9
# #     b = 0x8dcf3cf766e0b6c30e753416a70e2367
# #     m = 0x100000000000000000000000000000000


# #     for seed in range(0, m, m // 1000):  # Sample seeds
# #         try:
# #             decryptor = LCGDecryptor(seed, a, b, m)
# #             results = []
            
# #             for msg in encrypted_messages:
# #                 try:
# #                     decrypted = decryptor.decrypt(msg)
# #                     results.append(decrypted)
# #                 except Exception:
# #                     break
            
# #             # If we successfully decrypted all messages
# #             if len(results) == len(encrypted_messages):
# #                 print(f"Potential Match Found!")
# #                 print(f"Parameters: a={a}, b={b}, m={m}, seed={seed}")
# #                 print("Decrypted Messages:")
# #                 for r in results:
# #                     try:
# #                         print(r.decode('utf-8', errors='ignore'))
# #                     except:
# #                         print(r)
# #                 return
# #         except Exception:
# #             continue

# # def main():
# #     # Encrypted messages from the capture
# #     encrypted_messages = [
# #         "ocXzAq8Q",
# #         "kn4=",
# #         "2ulbTirRTzn+EKa1bvu3",
# #         "B3ljT4UTIVliEXzIoq8=",
# #         "4FfTtXHCD3LuRRJzLIzwyeylqqGwyTiugfjOo+MbNhyKv1ZDgSL33Lwaysu+dlONfwJ8jaqbuTVnVqwFloEI4wGdC9FFkmJgLpV9y3AZyjM0wsV+DRVR1cpOBvQqT4F46j2JiDxvABDqHRw5yrmv+uByJMyX/cZM2azJMonAVwV95ncUg0uWs3bmpturCW9sWiVaQ2pqjgAuUDs3Yab1/jJa4tthhkJrBJl6cyX88ijWqoMBKUkjsZ/sNa8uGLpC9gGpafUQwfyaPfImxIx8taB8bain59NlaI2RaL3YFfRrkxQAw8rUshLbxqI/AhpOH9LRQ09GeORcBnHPC0HaqMFDgp0euCJzrnVhdDmPrPPGhq/MsfISmr3R94HfOE4hs/h4ceMywp+qHOLZ/1RlvVoSBrK5w7o4G16PJLC9Xf8UzC6rQO5PQBiOcpNgCPg7NvToEickQd7CTBWQOEy+Rv0ar8gnTAooy2cjMe2iqeuEMTOd5Pz8QKS721vcxU4AU4cLDbwhr4tKteb3v3oGcAEiPF9sSoMbBlhoE0m7+f8wLPHvXrgfShSKBD0L9vccz42AMCUZGu+Ctw2QASe5apAnvWz0c+u3rD3aG8aXZo+hF3K4u7rjRkulqm2B+mD9aeJiVb2zlah74L6iRW0MUR7PvXkXSnnaX2sW8E9Y3obSBo2gEqcQAqhLAlsu7Y3y9Jyc87LJEMSf/tmq/BBEFIjcXXWBBO3ys1rK3vFdb5pfND6ApIO/AEhRoguD/SDGCpkOqkjXYk8cgSWaTE3aMULyhCZwFlHsyVMS9CodoFvAbInIEjE+L8ptHDff6IbbkENz/83i7SOGitFn3epsL0fyQjWlA5CSdceb/opVJVUeVwdYbVO4DC9XTRtDivq3VkbI0WL3cHUqmXcmAKzcGMSV/xkMB2Th6vAq+xcYhhm8EoFxqXC14e00/0XlvXm0pkZngfmo0Gd0qqJYofA34HS/Miuy6deJd5u3mnMeUGsv6O9mZ3VlpAUTQtEJXJvbzXbB7j+VPhb3J2JRRs+a9N2Is8jyyRO3tI7kmskDPRyMx1pg4jH138wWyqOvfWXVcTE+qNa+gh4VUZkDsaNE9H2+E/dyx2tKH78htEtT0zkU5tIOCzFl19odAJUdGapWjjqZmEBYKzGIdRF53KLK9qdmPczHycB8uYqRdNbLZixO2lIshAmGh1yx8ZKVGD1/RgFdPiE9k1YxHGQXd5Lmvg==",
# #         "kg4kSA=="
# #     ]

# #     brute_force_lcg(encrypted_messages)

# # if __name__ == "__main__":
# #     main()
















































# import base64

# class LCGDecryptor:
#     def __init__(self, seed, a, b, m):
#         self.seed = seed
#         self.a = a
#         self.b = b
#         self.m = m
#         self.state = seed

#     def next(self):
#         self.state = (self.a * self.state + self.b) % self.m
#         return self.state

#     def generate_key(self, length):
#         return bytes([self.next() & 0xff for _ in range(length)])

#     def decrypt(self, encrypted_msg):
#         encrypted_bytes = base64.b64decode(encrypted_msg)
#         key = self.generate_key(len(encrypted_bytes))
#         return bytes(x ^ y for x, y in zip(encrypted_bytes, key))

# def decrypt_messages(encrypted_messages, a, b, m, seed=0):
#     decryptor = LCGDecryptor(seed, a, b, m)
    
#     print("Decrypting messages:")
#     for i, msg in enumerate(encrypted_messages, 1):
#         try:
#             decrypted = decryptor.decrypt(msg)
#             print(f"Message {i}:")
#             print("Base64 Encoded:", msg)
#             print("Decrypted (bytes):", decrypted)
#             try:
#                 print("Decrypted (UTF-8):", decrypted.decode('utf-8', errors='replace'))
#             except Exception as e:
#                 print("Could not decode as UTF-8:", e)
#             print()
#         except Exception as e:
#             print(f"Error decrypting message {i}: {e}")

# def main():
#     # Parameters from the CTF challenge
#     a = 0xa1d41ebef9c575ac113fcfd5ac8dbda9
#     b = 0x8dcf3cf766e0b6c30e753416a70e2367
#     m = 0x100000000000000000000000000000000

#     # Encrypted messages from the capture
#     encrypted_messages = [
#         "ocXzAq8Q",
#         "kn4=",
#         "2ulbTirRTzn+EKa1bvu3",
#         "B3ljT4UTIVliEXzIoq8=",
#         "4FfTtXHCD3LuRRJzLIzwyeylqqGwyTiugfjOo+MbNhyKv1ZDgSL33Lwaysu+dlONfwJ8jaqbuTVnVqwFloEI4wGdC9FFkmJgLpV9y3AZyjM0wsV+DRVR1cpOBvQqT4F46j2JiDxvABDqHRw5yrmv+uByJMyX/cZM2azJMonAVwV95ncUg0uWs3bmpturCW9sWiVaQ2pqjgAuUDs3Yab1/jJa4tthhkJrBJl6cyX88ijWqoMBKUkjsZ/sNa8uGLpC9gGpafUQwfyaPfImxIx8taB8bain59NlaI2RaL3YFfRrkxQAw8rUshLbxqI/AhpOH9LRQ09GeORcBnHPC0HaqMFDgp0euCJzrnVhdDmPrPPGhq/MsfISmr3R94HfOE4hs/h4ceMywp+qHOLZ/1RlvVoSBrK5w7o4G16PJLC9Xf8UzC6rQO5PQBiOcpNgCPg7NvToEickQd7CTBWQOEy+Rv0ar8gnTAooy2cjMe2iqeuEMTOd5Pz8QKS721vcxU4AU4cLDbwhr4tKteb3v3oGcAEiPF9sSoMbBlhoE0m7+f8wLPHvXrgfShSKBD0L9vccz42AMCUZGu+Ctw2QASe5apAnvWz0c+u3rD3aG8aXZo+hF3K4u7rjRkulqm2B+mD9aeJiVb2zlah74L6iRW0MUR7PvXkXSnnaX2sW8E9Y3obSBo2gEqcQAqhLAlsu7Y3y9Jyc87LJEMSf/tmq/BBEFIjcXXWBBO3ys1rK3vFdb5pfND6ApIO/AEhRoguD/SDGCpkOqkjXYk8cgSWaTE3aMULyhCZwFlHsyVMS9CodoFvAbInIEjE+L8ptHDff6IbbkENz/83i7SOGitFn3epsL0fyQjWlA5CSdceb/opVJVUeVwdYbVO4DC9XTRtDivq3VkbI0WL3cHUqmXcmAKzcGMSV/xkMB2Th6vAq+xcYhhm8EoFxqXC14e00/0XlvXm0pkZngfmo0Gd0qqJYofA34HS/Miuy6deJd5u3mnMeUGsv6O9mZ3VlpAUTQtEJXJvbzXbB7j+VPhb3J2JRRs+a9N2Is8jyyRO3tI7kmskDPRyMx1pg4jH138wWyqOvfWXVcTE+qNa+gh4VUZkDsaNE9H2+E/dyx2tKH78htEtT0zkU5tIOCzFl19odAJUdGapWjjqZmEBYKzGIdRF53KLK9qdmPczHycB8uYqRdNbLZixO2lIshAmGh1yx8ZKVGD1/RgFdPiE9k1YxHGQXd5Lmvg==",
#         "kg4kSA=="
#     ]

#     decrypt_messages(encrypted_messages, a, b, m)

# if __name__ == "__main__":
#     main()





import base64
from Crypto.Util.strxor import strxor  # More efficient XOR for longer messages

class LCGDecryptor:
    def __init__(self, seed, a, b, m):
        self.state = seed
        self.a = a
        self.b = b
        self.m = m

    def _next(self):
        self.state = (self.a * self.state + self.b) % self.m
        return self.state

    def generate_key(self, length):
        return bytes([self._next() & 0xff for _ in range(length)])

    def decrypt(self, encrypted_msg):
        # Decode base64 first
        if isinstance(encrypted_msg, str):
            encrypted_msg = base64.b64decode(encrypted_msg)
        
        # Generate key of same length
        key = self.generate_key(len(encrypted_msg))
        
        # XOR decryption
        return strxor(encrypted_msg, key)

def decrypt_messages(encrypted_messages, seed, a, b, m):
    decryptor = LCGDecryptor(seed, a, b, m)
    
    print("Decrypting messages:")
    for i, msg in enumerate(encrypted_messages, 1):
        try:
            decrypted = decryptor.decrypt(msg)
            print(f"Message {i}:")
            print("Base64 Encoded:", msg)
            print("Decrypted (bytes):", decrypted)
            print("Decrypted (hex):", decrypted.hex())
            try:
                print("Decrypted (UTF-8):", decrypted.decode('utf-8', errors='replace'))
            except Exception as e:
                print("Could not decode as UTF-8:", e)
            print()
        except Exception as e:
            print(f"Error decrypting message {i}: {e}")

# Parameters from the setup
a = 0xa1d41ebef9c575ac113fcfd5ac8dbda9
b = 0x8dcf3cf766e0b6c30e753416a70e2367
m = 0x100000000000000000000000000000000

# Encrypted messages from the earlier capture
encrypted_messages = [
    "ocXzAq8Q",
    "kn4=",
    "2ulbTirRTzn+EKa1bvu3",
    "B3ljT4UTIVliEXzIoq8=",
    "4FfTtXHCD3LuRRJzLIzwyeylqqGwyTiugfjOo+MbNhyKv1ZDgSL33Lwaysu+dlONfwJ8jaqbuTVnVqwFloEI4wGdC9FFkmJgLpV9y3AZyjM0wsV+DRVR1cpOBvQqT4F46j2JiDxvABDqHRw5yrmv+uByJMyX/cZM2azJMonAVwV95ncUg0uWs3bmpturCW9sWiVaQ2pqjgAuUDs3Yab1/jJa4tthhkJrBJl6cyX88ijWqoMBKUkjsZ/sNa8uGLpC9gGpafUQwfyaPfImxIx8taB8bain59NlaI2RaL3YFfRrkxQAw8rUshLbxqI/AhpOH9LRQ09GeORcBnHPC0HaqMFDgp0euCJzrnVhdDmPrPPGhq/MsfISmr3R94HfOE4hs/h4ceMywp+qHOLZ/1RlvVoSBrK5w7o4G16PJLC9Xf8UzC6rQO5PQBiOcpNgCPg7NvToEickQd7CTBWQOEy+Rv0ar8gnTAooy2cjMe2iqeuEMTOd5Pz8QKS721vcxU4AU4cLDbwhr4tKteb3v3oGcAEiPF9sSoMbBlhoE0m7+f8wLPHvXrgfShSKBD0L9vccz42AMCUZGu+Ctw2QASe5apAnvWz0c+u3rD3aG8aXZo+hF3K4u7rjRkulqm2B+mD9aeJiVb2zlah74L6iRW0MUR7PvXkXSnnaX2sW8E9Y3obSBo2gEqcQAqhLAlsu7Y3y9Jyc87LJEMSf/tmq/BBEFIjcXXWBBO3ys1rK3vFdb5pfND6ApIO/AEhRoguD/SDGCpkOqkjXYk8cgSWaTE3aMULyhCZwFlHsyVMS9CodoFvAbInIEjE+L8ptHDff6IbbkENz/83i7SOGitFn3epsL0fyQjWlA5CSdceb/opVJVUeVwdYbVO4DC9XTRtDivq3VkbI0WL3cHUqmXcmAKzcGMSV/xkMB2Th6vAq+xcYhhm8EoFxqXC14e00/0XlvXm0pkZngfmo0Gd0qqJYofA34HS/Miuy6deJd5u3mnMeUGsv6O9mZ3VlpAUTQtEJXJvbzXbB7j+VPhb3J2JRRs+a9N2Is8jyyRO3tI7kmskDPRyMx1pg4jH138wWyqOvfWXVcTE+qNa+gh4VUZkDsaNE9H2+E/dyx2tKH78htEtT0zkU5tIOCzFl19odAJUdGapWjjqZmEBYKzGIdRF53KLK9qdmPczHycB8uYqRdNbLZixO2lIshAmGh1yx8ZKVGD1/RgFdPiE9k1YxHGQXd5Lmvg==",
    "kg4kSA=="
]

# Try decrypting with different seeds
seeds_to_try = [0, 1, 42, 12345, 54321]

for seed in seeds_to_try:
    print(f"\n--- Trying seed: {seed} ---")
    decrypt_messages(encrypted_messages, seed, a, b, m)