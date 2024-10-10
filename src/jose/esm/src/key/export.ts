import { toSPKI as exportPublic } from '../runtime/browser/asn1.js'
import type { KeyLike } from '../types.d.ts'

export const exportSPKI = (key: KeyLike) => exportPublic(key)
