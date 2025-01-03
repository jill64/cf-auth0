import type { Cookies } from '@sveltejs/kit'
import type { JWTHeaderParameters, JWTPayload } from 'jose'
import * as jwt from './jsonwebtoken'
import { JwksClient } from './jwks-rsa'

let cachedKey: string | undefined = undefined

const COOKIE_DURATION_SECONDS = 60 * 60 * 24 * 7 // 1 week

export const verifyToken = ({
  token,
  jwksUri
}: {
  token: string
  jwksUri: string
}) =>
  jwt.verify(token, async (header: JWTHeaderParameters) => {
    const client = new JwksClient({ jwksUri })

    const key = await client.getSigningKey(header.kid)

    if (cachedKey) {
      return cachedKey
    } else {
      const signingKey = key?.getPublicKey()
      cachedKey = signingKey
      return signingKey
    }
  })

export const getToken = async ({
  code,
  auth0_domain,
  auth0_client_id,
  auth0_client_secret,
  redirect_uri
}: {
  code: string
  auth0_domain: string
  auth0_client_id: string
  auth0_client_secret: string
  redirect_uri: string
}): Promise<{
  id_token: string
}> => {
  const resp = await fetch(`https://${auth0_domain}/oauth/token`, {
    method: 'POST',
    body: JSON.stringify({
      code,
      client_id: auth0_client_id,
      client_secret: auth0_client_secret,
      redirect_uri,
      grant_type: 'authorization_code'
    }),
    headers: {
      'Content-Type': 'application/json'
    }
  })

  return await resp.json()
}

export const getAuthUser = ({
  cookies,
  auth0_cookie_name
}: {
  cookies: Cookies
  auth0_cookie_name: string
}) => {
  const jwtToken = cookies.get(auth0_cookie_name)

  if (!jwtToken) {
    return null
  }

  return jwt.decode(jwtToken)
}

export const setAuthCookie = async ({
  cookies,
  payload,
  session_secret,
  auth0_cookie_name
}: {
  cookies: Cookies
  payload: JWTPayload
  session_secret: string
  auth0_cookie_name: string
}) => {
  const cookieValue = await jwt.sign(payload, session_secret)

  cookies.set(auth0_cookie_name, cookieValue, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: COOKIE_DURATION_SECONDS,
    path: '/'
  })
}
