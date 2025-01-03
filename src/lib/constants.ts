import { version } from '../../package.json'

async function generateHash(message: string) {
  // 文字列をエンコード（UTF-8バイト列へ変換）
  const encoder = new TextEncoder()
  const data = encoder.encode(message)

  // SHA-256 のハッシュ値を生成
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)

  // ArrayBuffer をバイト配列に変換
  const hashArray = Array.from(new Uint8Array(hashBuffer))

  // 各バイト値を16進数にして連結し、文字列に変換
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')

  return hashHex
}

const [DEFAULT_AUTH0_COOKIE_NAME] = await Promise.all([
  generateHash(version)
])

export { DEFAULT_AUTH0_COOKIE_NAME }
