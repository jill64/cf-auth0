export type AsymmetricKeyDetails =
  | {
      // DSA
      modulusLength: number
      divisorLength: number | undefined
    }
  | {
      // RSA
      modulusLength: number
      publicExponent: bigint
    }
  | {
      // RSA-PSS
      hashAlgorithm: string
      mgf1HashAlgorithm: string
      saltLength: number
    }
  | {
      // EC
      namedCurve: string | undefined
    }
