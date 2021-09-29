from typing import List
from functools import reduce
from values import sbox, sbox_inverse

################################################## UTILITIES ##################################################

def repr(m: List[int]):
  return ' '.join(list(map(lambda x: hex(x)[2:].zfill(2), m)))

def convert_to_ascii(message: str) -> List[int]:
  return list(map(lambda x: ord(x), message))

def convert_from_ascii(block: List[int]) -> str:
  return ''.join(list(map(lambda x: chr(x), block)))

def pad(block: List[int]) -> List[int]:
  missing = 16 - (len(block) % 16)
  return block + (missing * [missing])

def unpad(block: List[int]) -> List[int]:
  return block[:-block[-1]]

def split_to_blocks(message: List[int]) -> List[List[int]]:
  return [message[i*16:(i+1)*16] for i in range(len(message) // 16)]

def get_sbox_value(values: List[int]) -> List[int]:
  return [sbox[i] for i in values]

def get_inverse_sbox_value(values: List[int]) -> List[int]:
  return [sbox_inverse[i] for i in values]

def xor(*values: List[List[int]]):
  assert min(list(map(len, values))) == max(list(map(len, values))), 'Cannot XOR Lists, different list sizes.'
  return [reduce(lambda x, y: x ^ y, map(lambda z: z[i], values)) for i in range(min(list(map(len, values))))]

################################################## CONSTANTS ##################################################

rc = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def rcon(i: int) -> List[int]:
  return [rc[i], 0x00, 0x00, 0x00]

def n(key: List[int]) -> int:
  return [4, 6, 8][len(key) // 16 - 1]

def rounds(key: List[int]) -> int:
  return [10, 12, 14][len(key) // 16 - 1]

def split_key(k: List[int]) -> List[List[int]]:
  return [k[i*4:(i+1)*4] for i in range(len(k) // 4)]

################################################## SUBKEY GENERATION ##################################################

def generate_subkeys(key: List[int]) -> List[List[int]]:
  N = n(key)
  K = split_key(key)
  R = rounds(key) + 1
  W = []

  for i in range(R*4):
    if i < N:
      W += [K[i]]
    elif i >= N and i % N == 0:
      W += [xor(W[i - N], get_sbox_value(rotate(W[i - 1])), rcon(i // N))]
    elif i >= N and i % N == 4:
      W += [xor(W[i - N], get_sbox_value(W[i - 1]))]
    else:
      W += [xor(W[i - N], W[i - 1])]

  return [[el for arr in W[i*4:i*4+4] for el in arr] for i in range(R)]
  
def rotate(row: List[int], left=True) -> List[int]:
  return row[1:] + [row[0]] if left else [row[3]] + row[0:3]

def block_to_matrix(block: List[int]) -> List[List[int]]:
  return [[block[i*4+j] for i in range(16 // 4)] for j in range(16 // 4)]

def matrix_to_block(matrix: List[List[int]]) -> List[int]:
  return [matrix[i][j] for j in range(4) for i in range(4)]

################################################## MIX COLUMN UTILITIES ##################################################

def transpose_square_matrix(matrix: List[List[int]]) -> List[List[int]]:
  """ Transposes a square matrix to more easily access data elements """
  assert min(list(map(len, matrix))) == max(list(map(len, matrix))), 'Cannot transpose this matrix. Matrix definition unbalanced.'
  assert max(list(map(len, matrix))) == len(matrix), 'Cannot transpose this matrix. Matrix is not square.'
  return [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix))]

def shift_row(matrix: List[List[int]], left=True):
  """ Performs a linear shift of the rows of a matrix. The direction of the shift can be toggled. """
  for i in range(len(matrix)):
    for _ in range(i):
      matrix[i] = rotate(matrix[i], left=left)
  return matrix

def gf_multiplication(pn1: int, pn2: int) -> int:
  """ Russian Peasant Multiplication algorithm, used to factor polynomials efficiently in GF(2^n) """
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

def mix_column(fixed_matrix: List[List[int]], matrix: List[List[int]]) -> List[List[int]]:
  """ Performs the Mix Column operation on a matrix (profided with a fixed matrix that is used as a GF reference). """
  assert min(list(map(len, fixed_matrix))) == max(list(map(len, fixed_matrix))) and min(list(map(len, matrix))) == max(list(map(len, matrix))), 'Cannot mix these matrices. Matrix definition unbalanced.'
  assert min(list(map(len, fixed_matrix))) == max(list(map(len, matrix))), 'Matrix definition unequal.'

  size = min(list(map(len, fixed_matrix)))
  return [[reduce(lambda x, y: x ^ y, [gf_multiplication(a, b) for a, b in zip(fixed_matrix[i], transpose_square_matrix(matrix=matrix)[j])]) for j in range(size)] for i in range(size)]

################################################## AES ENCRYPTION & DECRYPTION ##################################################

def aes_encrypt(msg: List[int], key: List[int]):
  """ Encrypts a given message with a given key. """
  assert len(key) * 8 in [128, 192, 256], 'Key size must be 128, 192 or 256 bits (16, 24 or 32 characters)'
  
  gf_matrix = block_to_matrix([0x02, 0x01, 0x01, 0x03, 0x03, 0x02, 0x01, 0x01, 0x01, 0x03, 0x02, 0x01, 0x01, 0x01, 0x03, 0x02])
  subkeys = generate_subkeys(key=key)
  
  msg = pad(msg)
  blocks = split_to_blocks(message=msg)

  for i in range(len(blocks)):
    blocks[i] = xor(blocks[i], subkeys[0])

    for s in range(1, len(subkeys)):
      blocks[i] = shift_row(block_to_matrix(get_sbox_value(blocks[i])), True)
      if s != len(subkeys) - 1:
        blocks[i] = mix_column(gf_matrix, blocks[i])
      blocks[i] = xor(matrix_to_block(blocks[i]), subkeys[s])
  return [item for block in blocks for item in block]

def aes_decrypt(msg: List[int], key: List[int]):
  """ Decrypts a given message with a given key. """
  assert len(key) * 8 in [128, 192, 256], 'Key size must be 128, 192 or 256 bits (16, 24 or 32 characters)'

  gf_matrix = block_to_matrix([0x0e, 0x09, 0x0d, 0x0b, 0x0b, 0x0e, 0x09, 0x0d, 0x0d, 0x0b, 0x0e, 0x09, 0x09, 0x0d, 0x0b, 0x0e])
  subkeys = generate_subkeys(key=key)

  blocks = split_to_blocks(message=msg)

  for i in range(len(blocks)):
    for s in range(len(subkeys) - 1, 0, -1):
      blocks[i] = block_to_matrix(xor(blocks[i], subkeys[s]))
      if s != len(subkeys) - 1:
        blocks[i] = mix_column(gf_matrix, blocks[i])
      blocks[i] = get_inverse_sbox_value(matrix_to_block(shift_row(blocks[i], False)))

    blocks[i] = xor(blocks[i], subkeys[0])
  
  return unpad([item for block in blocks for item in block])

################################################## TEST & EXECUTION ##################################################

def test(msg: str, key: str):
  """ Checks whether or not the provided AES algorithm works at encoding and decoding a specific string for a specific key. """
  _msg = convert_to_ascii(msg)
  _key = convert_to_ascii(key)
  
  print('Original Plaintext:\t', msg)
  print('Key:\t\t\t', key, '\n')
  print('Original:\t\t', repr(_msg))
  msg_encrypted = aes_encrypt(msg=_msg, key=_key)
  print('Encrypted:\t\t', repr(msg_encrypted), '\n')
  msg_decrypted = aes_decrypt(msg=msg_encrypted, key=_key)
  print('Decrypted:\t\t', repr(msg_decrypted))
  print('Decrypted Plaintext:\t', convert_from_ascii(msg_decrypted))

  assert msg_decrypted == _msg, 'AES does not work'
  print('\n', '#' * 150, '\n', sep='')

if __name__ == '__main__':
  test('Two One Nine Two', 'Thats my Kung Fu')
  test('Can you smell what the Rock is cooking?', 'You can\'t see me')