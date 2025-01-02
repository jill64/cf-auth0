import { subtle } from 'node:crypto'

const extractBase64FromPem = (pemString: string) => {
  // 行単位で処理するため、改行を全て取り除きやすい形に整形
  const lines = pemString
    .trim() // 前後の空白除去
    .split('\n') // 改行で分割
    .map((line) => line.trim()) // 各行の空白除去

  // -----BEGIN PUBLIC KEY----- や -----END PUBLIC KEY----- などの行を除外し、
  // 残った本文だけを連結する
  const base64Lines = lines.filter((line) => {
    return !line.startsWith('-----BEGIN') && !line.startsWith('-----END')
  })

  // Base64 部分を一つの文字列に連結
  const base64String = base64Lines.join('')

  return base64String
}

const base64ToArrayBuffer = (base64String: string) => {
  const binaryString = atob(base64String) // Base64 → バイナリ文字列
  const length = binaryString.length
  const bytes = new Uint8Array(length)

  for (let i = 0; i < length; i++) {
    bytes[i] = binaryString.charCodeAt(i)
  }

  return bytes.buffer // ArrayBuffer を返す
}

const importRSAPublicKey = async (spkiBuffer: ArrayBuffer) => {
  // RSA-PSS (署名検証用) の例
  return await subtle.importKey(
    'spki', // 公開鍵 → "spki" 形式
    spkiBuffer, // ArrayBuffer データ
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' } // ハッシュアルゴリズム
    },
    true, // 抽出可能にするかどうか（用途に合わせて設定）
    ['verify'] // 公開鍵の用途 ["verify"] / ["encrypt"] など
  )
}

export const createPublicKey = async (pemPublicKeyString: string) => {
  const base64String = extractBase64FromPem(pemPublicKeyString)
  const spkiBuffer = base64ToArrayBuffer(base64String)
  const publicKey = await importRSAPublicKey(spkiBuffer)
  return publicKey
}
