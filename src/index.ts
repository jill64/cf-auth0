import { Cookies } from '@sveltejs/kit'
import * as jwt from './jsonwebtoken/esm/index.js'
import { JwksClient } from './jwks-rsa/esm/src/index.js'

const COOKIE_DURATION_SECONDS = 60 * 60 * 24 * 7 // 1 week

let cached_key: string | undefined = undefined

export const CfAuth0 = ({
  auth0_client_id,
  auth0_client_secret,
  auth0_domain,
  auth0_cookie_name,
  jwks_url,
  session_secret,
  base_url
}: {
  auth0_client_id: string
  auth0_client_secret: string
  auth0_domain: string
  auth0_cookie_name: string
  jwks_url: string
  session_secret: string
  base_url: string
}) => {
  const getKey = async (
    header: jwt.JwtHeader,
    callback: jwt.SigningKeyCallback
  ) => {
    try {
      const client = new JwksClient({ jwksUri: jwks_url })

      const key = await client.getSigningKey(header.kid)

      if (cached_key) {
        callback(null, cached_key)
      }

      const signingKey = key?.getPublicKey()
      cached_key = signingKey
      callback(null, signingKey)
    } catch (err) {
      callback(err as Error)
    }
  }

  const verifyToken = (token: string): Promise<jwt.JwtPayload | string> => {
    return new Promise((resolve, reject) => {
      jwt.verify(token, getKey, {}, (err, payload) => {
        if (err || !payload) {
          return reject(err)
        }
        return resolve(payload)
      })
    })
  }

  const getToken = async ({
    code
  }: {
    code: string
  }): Promise<{
    id_token: string
  }> => {
    const res = await fetch(`https://${auth0_domain}/oauth/token`, {
      method: 'POST',
      body: JSON.stringify({
        code,
        client_id: auth0_client_id,
        client_secret: auth0_client_secret,
        redirect_uri: `${base_url}/api/auth/callback`,
        grant_type: 'authorization_code'
      }),
      headers: {
        'Content-Type': 'application/json'
      }
    })

    return await res.json()
  }

  const getAuthUser = (cookies: Cookies) => {
    const jwtToken = cookies.get(auth0_cookie_name)

    if (!jwtToken) {
      return null
    }

    return jwt.decode(jwtToken)
  }

  const verify = (
    token: string,
    secretOrPublicKey: jwt.Secret | jwt.PublicKey | jwt.GetPublicKeyOrSecret
  ) => {
    return jwt.verify(token, secretOrPublicKey)
  }

  const setAuthCookie = (cookies: Cookies, user: jwt.JwtPayload | string) => {
    const cookieValue = jwt.sign(user, session_secret)
    cookies.set(auth0_cookie_name, cookieValue, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: COOKIE_DURATION_SECONDS,
      path: '/'
    })
  }

  return {
    getToken,
    getAuthUser,
    verify,
    setAuthCookie,
    verifyToken
  }
}
