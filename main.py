from typing import List
from functools import reduce
from values import sbox, sbox_inverse

def debug(m: List[int]):
  print(' '.join(list(map(lambda x: hex(x)[2:].zfill(2), m))))

def debug2(m: List[List[int]]): 
  for _m in m:
    print(' '.join(list(map(lambda x: hex(x)[2:].zfill(2), _m))))
#####################################################################

rc = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def rcon(i: int) -> List[int]:
  return [rc[i], 0x00, 0x00, 0x00]

def n(key: List[int]) -> int:
  return [4, 6, 8][len(key) // 16 - 1]



def convert(message: str) -> List[int]:
  return list(map(lambda x: ord(x), message))

def pad(block: List[int]) -> List[int]:
  missing = 16 - (len(block) % 16)
  padded = block + (missing * [missing])
  return padded

def split_to_blocks(message: List[int]) -> List[List[int]]:
  return [message[i*16:(i+1)*16] for i in range(len(message) // 16)]
  
def split_key(k: List[int]) -> List[List[int]]:
  return [k[i*4:(i+1)*4] for i in range(len(k) // 4)]

def rounds(key: List[int]) -> int:
  return [10, 12, 14][len(key) // 16 - 1]

def expand_key(key: List[int]) -> List[List[int]]:
  N = n(key)
  print(N)
  K = split_key(key)
  R = rounds(key) + 1

  W = []
  for i in range(R*4):
    if i < N:
      W += [K[i]]
    elif i >= N and i % N == 0:
      W += [xor(W[i - N], SBox(rotate(W[i - 1])), rcon(i // N))]
    elif i >= N and i % N == 4:
      W += [xor(W[i - N], SBox(W[i - 1]))]
    else:
      W += [xor(W[i - N], W[i - 1])]

  return [[el for arr in W[i*4:i*4+4] for el in arr] for i in range(R)]
  
def rotate(row: List[int]) -> List[int]:
  return row[1:] + [row[0]]

def block_to_matrix(block: List[int]) -> List[List[int]]:
  return [[block[i*4+j] for i in range(16 // 4)] for j in range(16 // 4)]

def shift_row(matrix: List[List[int]]):
  for i in range(len(matrix)):
    for j in range(i):
      matrix[i] = rotate(matrix[i])
  return matrix

def gf_multiplication(pn1: int, pn2: int) -> int:
  """ Russian Peasant Multiplication algorithm """
  p = 0
  while pn1 > 0 and pn2 > 0:
    if pn2 & 1 != 0:
      p ^= pn1
    if pn1 & 0x80 != 0:
      pn1 = (pn1 << 1) ^ 0x11b
    else:
      pn1 <<= 1
    
    pn2 >>= 1
  return p

def aes_encrypt(_message: str, _key: str):
  assert len(_key) * 8 in [128, 192, 256], 'Key size must be 128, 192 or 256 bits (16, 24 or 32 characters)'

  gf_matrix = block_to_matrix([0x02, 0x01, 0x01, 0x03, 0x03, 0x02, 0x01, 0x01, 0x01, 0x03, 0x02, 0x01, 0x01, 0x01, 0x03, 0x02])
  debug2(gf_matrix)
  msg = convert(_message)
  key = convert(_key)

  subkeys = expand_key(key=key)
  blocks = split_to_blocks(message=msg)

  for i in range(len(blocks)):
    round0 = subkeys[0]
    blocks[i] = xor(blocks[i], subkeys[0])
    blocks[i] = SBox(blocks[i])
    blocks[i] = block_to_matrix(blocks[i])
    blocks[i] = shift_row(blocks[i])
    debug2(blocks[i])

    
    for s in range(1, len(subkeys)):
      
      pass

    break
  pass

def SBox(values: List[int]) -> List[int]:
  return [sbox[i] for i in values]

def xor(*values: List[List[int]]):
  assert min(list(map(len, values))) == max(list(map(len, values))), 'Cannot XOR Lists, different list sizes.'
  assert len(values) >= 2, 'Must XOR more than one list.'
  return [reduce(lambda x, y: x ^ y, map(lambda z: z[i], values)) for i in range(min(list(map(len, values))))]

if __name__ == '__main__':
  msg = 'Two One Nine Two'
  key = 'Thats my Kung Fu'
  
  #print(block_to_matrix(split(pad(msg))[0]))
  #aes_encrypt(_message=msg, _key=key)

  ba = gf_multiplication(0x02, 0x63) ^ gf_multiplication(0x03, 0x2f) ^ gf_multiplication(0x01, 0xAF) ^ gf_multiplication(0x01, 0xA2)
  x = gf_multiplication(0x02, 0xEB) ^ gf_multiplication(0x03, 0x93) ^ gf_multiplication(0x01, 0xC7) ^ gf_multiplication(0x01, 0x20)

  print(hex(ba)[2:])
  print(hex(x)[2:])