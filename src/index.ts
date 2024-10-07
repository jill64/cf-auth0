import type { Cookies } from '@sveltejs/kit'
import type {
  JwtHeader,
  JwtPayload,
  SigningKeyCallback
} from './jsonwebtoken/esm/index.d.ts'
import * as jwt from './jsonwebtoken/esm/index.js'
import { JwksClient } from './jwks-rsa/esm/src/index.js'

const COOKIE_DURATION_SECONDS = 60 * 60 * 24 * 7 // 1 week

let cached_key: string | undefined = undefined

export class CfAuth0 {
  private auth0_client_id
  private auth0_client_secret
  private auth0_domain
  private auth0_cookie_name
  private jwks_url
  private session_secret
  private base_url

  constructor(arg: {
    auth0_client_id: string
    auth0_client_secret: string
    auth0_domain: string
    auth0_cookie_name: string
    jwks_url: string
    session_secret: string
    base_url: string
  }) {
    this.auth0_client_id = arg.auth0_client_id
    this.auth0_client_secret = arg.auth0_client_secret
    this.auth0_domain = arg.auth0_domain
    this.auth0_cookie_name = arg.auth0_cookie_name
    this.jwks_url = arg.jwks_url
    this.session_secret = arg.session_secret
    this.base_url = arg.base_url
  }

  private async getKey(header: JwtHeader, callback: SigningKeyCallback) {
    const client = new JwksClient({ jwksUri: this.jwks_url })

    try {
      // @ts-expect-error TODO
      client.getSigningKey(header.kid, (err, key) => {
        if (err) {
          callback(err as Error)
          throw err
        }

        if (cached_key) {
          callback(null, cached_key)
        }

        const signingKey = key?.getPublicKey()
        cached_key = signingKey
        callback(null, signingKey)
      })
    } catch (err) {
      console.log('debug5.1.2.1')
      callback(err as Error)
    }
  }

  verifyToken(token: string): Promise<JwtPayload | string> {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.getKey, {}, (err, payload) => {
        if (err || !payload) {
          return reject(err)
        }
        return resolve(payload)
      })
    })
  }

  async getToken({ code }: { code: string }): Promise<{
    id_token: string
  }> {
    const res = await fetch(`https://${this.auth0_domain}/oauth/token`, {
      method: 'POST',
      body: JSON.stringify({
        code,
        client_id: this.auth0_client_id,
        client_secret: this.auth0_client_secret,
        redirect_uri: `${this.base_url}/api/auth/callback`,
        grant_type: 'authorization_code'
      }),
      headers: {
        'Content-Type': 'application/json'
      }
    })

    return await res.json()
  }

  getAuthUser(cookies: Cookies) {
    const jwtToken = cookies.get(this.auth0_cookie_name)

    if (!jwtToken) {
      return null
    }

    return jwt.decode(jwtToken)
  }

  verify(
    token: Parameters<typeof jwt.verify>[0],
    secretOrPublicKey: Parameters<typeof jwt.verify>[1],
    options: Parameters<typeof jwt.verify>[2]
  ) {
    return jwt.verify(token, secretOrPublicKey, options)
  }

  setAuthCookie(cookies: Cookies, user: JwtPayload | string) {
    const cookieValue = jwt.sign(user, this.session_secret)
    cookies.set(this.auth0_cookie_name, cookieValue, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: COOKIE_DURATION_SECONDS,
      path: '/'
    })
  }
}
