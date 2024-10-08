import { toSPKI as exportPublic } from '../runtime/browser/asn1.js'
import type { KeyLike } from '../types.d.ts'

export async function exportSPKI(key: KeyLike): Promise<string> {
  return exportPublic(key)
}
