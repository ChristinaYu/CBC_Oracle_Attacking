from __future__ import print_function
"""
/************************************************************************/
/* Program: CBC Padding Oracle Attacks                                  */
/* Course:  CS544                                                       */
/* Author: Xuan Yu                                                      */
/* Date: 2017-3-23                                                      */
/* Notes: 1. This file takes 2 blocks(including IV) and output the      */
/*           plaintext. So for a 9-block ciphertexts, we need to run the*/
/*           file for each block individually, 9 times total.           */
/*        2. The last block has a padding 0x05 * 5. And 2 values make   */
/*           the padding successful. So to get the correct value,       */
/*           uncomment the if loop in line 86 and 87 for the last block.*/ 
/************************************************************************/
"""

"""Client.py

   This module is the python code that can be used to connect to the Oracle and manipulate the ciphertext. 
   It takes 4 arguments:

     1. -ip (--ipaddress):  The IP address of the machine to run the server.
     2. -p (--port):        The port to listen on.
     3. -b (--block):       The 32-byte block sent to the server
     4. -id (--keyid):      The unique keyid that was assigned to each student       

   Feed 'client.py' a 32 hex-byte chunk concatenated where:
   - The first 16 hex-bytes are the block (initialization vector) that can be used to manipulate the Oracle. 
   - The second 16 hex-bytes are the block of data that should be decrypted.

   Each student has a unique keyid assigned, which corresponds to a secret key that is unique to their encrypted text. 
   The server will respond to the client with 'Message decrypted successfully' (valid padding) if the input decrypts with successful padding 
   And "Padding error during decryption" (invalid padding) otherwise.
   The server will only check padding for 2 blocks at the time (iv + ciphertext), if more blocks are sent it will check padding on the last two blocks.

   *Note* A hex byte is two chars (00, fe, ab, etc..) so two blocks of size 16 should be 64 TOTAL in length!

   Example usage:
   python client.py -ip localhost -p 10000 -b '0000000000000000000000000000000ec41cb170426f83ef05538c51ca28bbf3' -id 00

   In this case the IV is: 0000000000000000000000000000000e
   And the cipher text is:  c41cb170426f83ef05538c51ca28bbf3'
"""
# Dependencies
import argparse
import socket
import sys
import binascii

# Length of either response.
# Server response may have spaces in it
# to adhere to message length
MESSAGE_LENGTH = 32
BLOCK_SIZE = 32
def prRed(prt): print("\033[91m{}\033[00m".format(prt), end="")
def prCyan(prt): print("\033[36m{}\033[00m".format(prt), end="")
def prGray(prt): print("\033[90m{}\033[00m".format(prt), end="")

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress", help='ip address where the server is running', required=True)
parser.add_argument("-p", "--port", help='port where the server is listening on', required=True)
parser.add_argument("-b", "--block", help='the 32-byte block sent to the server', required=True)
parser.add_argument("-id", "--keyid", help='unique key id', required=True)
args = parser.parse_args()

cipher_size = len(args.block)
ciphertext_hex = args.block
ciphertext = binascii.unhexlify(ciphertext_hex)



if not(cipher_size % BLOCK_SIZE == 0):
  print ("Bad block(s) size")
  exit()

else:
  num_blocks = (cipher_size/BLOCK_SIZE)-1 # num_blocks to be decrypted (IV not counting as ciphertext block)

  previousCipherBlock = list(ciphertext[0:16])
  currCipherBlock = ciphertext[16:32]
  iv = list(ciphertext[0:16])
  # print("previousCipherBlock: "+str(previousCipherBlock))
  # print("iv:  "+str(iv))
  # print("currCipherBlock:   "+str(currCipherBlock))

  result = []
  iv_behind = [1]*16

  for j in range(1, 17): # the byte in the block(in reverse order)
    iv_front = iv[0:16-j]
    print(" ")
    for i in range(0, 256): # All possibilities of iv[-j]
      # below 'if loop' is only needed for the last block, as it has 2 values make padding successful
      if(j==1 and i == 42):
        continue
      
      # iv_behind = iv[16-j+1:16]
      if len(str(hex(i)[2:])) == 1: padding = "0"
      else: padding = ""

      # Create a TCP/IP socket
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # Connect the socket to the port where the server is listening
      server_address = (args.ipaddress, int(args.port))
      sock.connect(server_address)

      iv[-j] = i #count from right to left the j'th item
      # print("1st: iv[-j]: "+str(iv[-j])+", j: "+str(j)+", previousCipherBlock[-j]: "+str(binascii.hexlify(bytearray(previousCipherBlock[-j]))))

      
      # Send data
      message = binascii.hexlify(bytearray(iv)).decode() + binascii.hexlify(bytearray(currCipherBlock)).decode() + ':' + str(num_blocks) + ':' + args.keyid  
      sock.sendall(message)
      # print(message)

      # Look for the response
      ciphertext = sock.recv(MESSAGE_LENGTH)
      # print(ciphertext)
      if "successfully" in ciphertext:      
        break
      sock.close()

      # print(" ",end="")
      print(str(j)+" / 16: "+" IV-> ", end="")
      print(binascii.hexlify(bytearray(iv_front)).decode(), end="")
      prRed(padding + str(hex(i)[2:]))
      if iv_behind[-1] != 1: prCyan(binascii.hexlify(bytearray(iv_behind[1-j:])).decode())
      print(" Cipher-> ", end="")
      print(binascii.hexlify(bytearray(currCipherBlock)).decode()+" Plain-> ", end="")
      print(result)

    result.insert(0,iv[-j] ^ j ^ ord(previousCipherBlock[-j]))
    # iv_behind.append(iv_behind)


    # j is the padding
    for i in range(1, j + 1):
      iv[-i] = iv[-i] ^ j ^ (j + 1)
      iv_behind[-i] = iv[-i]


  # result.reverse()
  # print(" ",end="")
  print(str(j)+" / 16: "+" IV-> ", end="")
  prGray(binascii.hexlify(bytearray(iv_front)).decode())
  prCyan(padding + str(hex(i)[2:]))
  if iv_behind[-1] != 1: print(binascii.hexlify(bytearray(iv_behind[1-j:])).decode(), end="")
  print(" Cipher-> ", end="")
  print(binascii.hexlify(bytearray(currCipherBlock)).decode()+" Plain-> ", end="")
  print(result)
  print("\n")
  print("Block 1:")
  prRed(bytearray(result).decode())
  print("\n")
  # print("Final Decrypted Texts:")
  # result = [116, 111, 32, 116, 104, 101, 10, 10, 73, 78, 72, 65, 66, 73, 84, 65,
  # 78, 84, 83, 10, 10, 111, 102, 10, 10, 65, 77, 69, 82, 73, 67, 65,
  # 44, 10, 10, 79, 110, 32, 116, 104, 101, 32, 102, 111, 108, 108, 111, 119,
  # 105, 110, 103, 32, 105, 110, 116, 101, 114, 101, 115, 116, 105, 110, 103, 10,
  # 10, 83, 85, 66, 74, 69, 67, 84, 83, 10, 10, 32, 32, 32, 32, 79,
  # 102, 32, 116, 104, 101, 32, 79, 114, 105, 103, 105, 110, 32, 97, 110, 100,
  # 32, 68, 101, 115, 105, 103, 110, 32, 111, 102, 32, 71, 111, 118, 101, 114,
  # 110, 109, 101, 110, 116, 32, 105, 110, 32, 103, 101, 110, 101, 114, 97, 108,
  # 44, 10, 32, 32, 32, 32, 119, 105, 116, 104, 32, 5, 5, 5, 5, 5]
  # prRed(bytearray(result).decode())
  # print("\n")

