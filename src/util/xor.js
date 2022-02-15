function xor (a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new Error('Arguments must be buffers')
  }
  if (a.length !== b.length) {
    throw new Error('Buffers must be the same length')
  }
  const result = Buffer.alloc(a.length)
  for (let i = 0; i < a.length; i++) {
    result[i] = a[i] ^ b[i]
  }
  return result
}

export default xor
