// Minimal base58btc (Bitcoin alphabet) codec for multicodec multibase keys.
// No external dependency — the algorithm is small and well-defined.

import { ConnectxError } from '../errors'

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const BASE = 58n

const INDEX = new Map([...ALPHABET].map((ch, i) => [ch, BigInt(i)]))

export function base58btcDecode(input: string): Uint8Array {
  let num = 0n
  for (const ch of input) {
    const val = INDEX.get(ch)
    if (val === undefined) throw new ConnectxError('key_invalid', `Invalid base58 character: "${ch}"`)
    num = num * BASE + val
  }

  // Leading '1' characters encode leading zero bytes.
  let lead = 0
  while (lead < input.length && input[lead] === '1') lead++

  const bytes: number[] = []
  while (num > 0n) {
    bytes.unshift(Number(num % 256n))
    num /= 256n
  }
  return new Uint8Array([...new Array(lead).fill(0), ...bytes])
}

export function base58btcEncode(data: Uint8Array): string {
  let lead = 0
  while (lead < data.length && data[lead] === 0) lead++

  let num = 0n
  for (let i = lead; i < data.length; i++) num = num * 256n + BigInt(data[i])

  let out = ''
  while (num > 0n) {
    out = ALPHABET[Number(num % 58n)] + out
    num /= 58n
  }
  return '1'.repeat(lead) + out
}
