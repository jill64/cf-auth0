import * as jwt from '$lib/server/auth/jsonwebtoken'
import { attempt } from '@jill64/attempt'
import type { Cookies } from '@sveltejs/kit'
import type { JWTHeaderParameters, JWTPayload } from 'jose'
import crypto from 'node:crypto'
import { JwksClient } from './server/auth/jwks-rsa'

const COOKIE_DURATION_SECONDS = 60 * 60 * 24 * 7 // 1 week

interface Auth0TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  scope: string
}

export class CfAuth0 {
  private auth0ClientId
  private auth0ClientSecret
  private auth0Domain
  private auth0CustomDomain
  private baseUrl
  private auth0CookieName
  private sessionSecret
  private callbackPath
  private loginPath
  private logoutPath
  private isSvelteKit
  private jwtPayload: JWTPayload = {}
  private cachedKey: string | undefined = undefined

  constructor({
    auth0CookieName = 'auth0',
    sessionSecret,
    auth0ClientId,
    auth0ClientSecret,
    auth0Domain,
    auth0CustomDomain = auth0Domain,
    baseUrl,
    callbackPath,
    loginPath,
    logoutPath,
    isSvelteKit
  }: {
    auth0ClientId: string

    auth0ClientSecret: string

    /** @example 'example.us.auth0.com' */
    auth0Domain: string

    /** @example 'auth.example.com' */
    auth0CustomDomain?: string

    /** @example 'http://localhost:3000' */
    baseUrl: string

    /** @example '/api/auth/callback' */
    callbackPath: string

    /** @example '/api/auth/login' */
    loginPath: string

    /** @example '/api/auth/logout' */
    logoutPath: string

    auth0CookieName?: string
    sessionSecret: string
    isSvelteKit?: boolean
  }) {
    this.auth0ClientId = auth0ClientId
    this.auth0ClientSecret = auth0ClientSecret
    this.auth0Domain = auth0Domain
    this.auth0CustomDomain = auth0CustomDomain
    this.baseUrl = baseUrl
    this.auth0CookieName = auth0CookieName
    this.sessionSecret = sessionSecret
    this.callbackPath = callbackPath
    this.loginPath = loginPath
    this.isSvelteKit = isSvelteKit
    this.logoutPath = logoutPath
  }

  /** Please redirect to return URL after calling this function */
  async auth({
    cookies,
    url
  }: {
    cookies: Cookies
    /** @description current location */
    url: URL
  }) {
    const cookie = cookies.get(this.auth0CookieName)

    if (cookie) {
      const payload = await attempt(
        () => jwt.verify(cookie, this.sessionSecret),
        () => {
          cookies.delete(this.auth0CookieName, { path: '/' })
          return this.baseUrl
        }
      )

      if (typeof payload === 'string') {
        return payload
      }

      await this.setAuthCookie({
        cookies,
        payload
      })

      this.jwtPayload = payload

      return payload
    }

    const { pathname, search, hash } = url

    return `${this.loginPath}?returnUrl=${pathname}${search}${hash}`
  }

  /** Please redirect to return URL after calling this function */
  login({
    cookies,
    url
  }: {
    cookies: Cookies
    /** @description current location */
    url: URL
  }) {
    const csrfState = crypto.randomBytes(16).toString('hex')

    cookies.set('csrfState', csrfState, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 1000,
      path: '/'
    })

    const returnUrl = encodeURIComponent(
      url.searchParams.get('returnUrl') || '/'
    )

    const query = {
      scope: 'openid profile email',
      response_type: 'code',
      client_id: this.auth0ClientId,
      redirect_uri: `${this.baseUrl}${this.callbackPath}?returnUrl=${returnUrl}`,
      state: csrfState
    }

    return `https://${this.auth0CustomDomain}/authorize?${new URLSearchParams(
      query
    ).toString()}`
  }

  private async verifyToken(token: string) {
    return jwt.verify(token, async (header: JWTHeaderParameters) => {
      const client = new JwksClient({
        jwksUri: `https://${this.auth0Domain}/.well-known/jwks.json`
      })

      const key = await client.getSigningKey(header.kid)

      if (this.cachedKey) {
        return this.cachedKey
      } else {
        const signingKey = key?.getPublicKey()
        this.cachedKey = signingKey
        return signingKey
      }
    })
  }

  private async getToken({
    code,
    redirect_uri
  }: {
    code: string
    redirect_uri: string
  }): Promise<{
    id_token: string
  }> {
    const resp = await fetch(`https://${this.auth0Domain}/oauth/token`, {
      method: 'POST',
      body: JSON.stringify({
        code,
        client_id: this.auth0ClientId,
        client_secret: this.auth0ClientSecret,
        redirect_uri,
        grant_type: 'authorization_code'
      }),
      headers: {
        'Content-Type': 'application/json'
      }
    })

    return await resp.json()
  }

  private async getAuthUser(cookies: Cookies) {
    const jwtToken = cookies.get(this.auth0CookieName)

    if (!jwtToken) {
      return null
    }

    return jwt.decode(jwtToken)
  }

  /** Please redirect to return URL after calling this function */
  logout({
    cookies,
    returnUrl = this.baseUrl
  }: {
    cookies: Cookies
    returnUrl?: string
  }) {
    cookies.delete(this.auth0CookieName, { path: '/' })

    return `https://${this.auth0CustomDomain}/logout?client_id=${this.auth0ClientId}&returnTo=${returnUrl}`
  }

  async callback({
    cookies,
    url
  }: {
    cookies: Cookies
    /** @description current location */
    url: URL
  }) {
    const code = url.searchParams.get('code')
    const state = url.searchParams.get('state')
    let returnUrl = url.searchParams.get('returnUrl') || '/'

    if (this.isSvelteKit && returnUrl.includes('/__data.json')) {
      returnUrl = returnUrl.replace('/__data.json', '')
    }

    const csrfState = cookies.get('csrfState')

    if (state !== csrfState || !code) {
      if (csrfState === undefined) {
        return this.loginPath
      }
      throw new Error('Invalid state')
    }

    const token = await this.getToken({
      code,
      redirect_uri: `${this.baseUrl}${this.callbackPath}`
    })

    const authUser = await this.verifyToken(token.id_token)

    await this.setAuthCookie({
      cookies,
      payload: authUser
    })

    cookies.delete('csrfState', { path: '/' })

    return returnUrl
  }

  async delete() {
    const accessToken = await this.getManagementApiToken()
    await this.deleteAuth0User(accessToken)
    return this.logoutPath
  }

  async changeEmail(newEmail: string) {
    const accessToken = await this.getManagementApiToken()
    await this.changeUserEmail(newEmail, accessToken)
    return this.logoutPath
  }

  private async getManagementApiToken(): Promise<string> {
    const url = `https://${this.auth0Domain}/oauth/token`

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_id: this.auth0ClientId,
        client_secret: this.auth0ClientSecret,
        audience: `https://${this.auth0Domain}/api/v2/`,
        grant_type: 'client_credentials'
      })
    })

    if (!response.ok) {
      throw new Error(
        `Failed to Get Token Error: ${response.status} ${response.statusText}`
      )
    }

    const data = (await response.json()) as Auth0TokenResponse
    return data.access_token
  }

  private async deleteAuth0User(accessToken: string): Promise<void> {
    console.log('this.jwtPayload.sub', this.jwtPayload.sub)

    const url = `https://${this.auth0Domain}/api/v2/users/${encodeURIComponent(
      this.jwtPayload.sub!
    )}`

    const response = await fetch(url, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    })

    if (!response.ok) {
      throw new Error(
        `Failed to Get Token: ${response.status} ${response.statusText}`
      )
    }
  }
  private async changeUserEmail(
    newEmail: string,
    accessToken: string
  ): Promise<void> {
    const url = `https://${this.auth0Domain}/api/v2/users/${encodeURIComponent(
      this.jwtPayload.sub!
    )}`

    const res = await fetch(url, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: newEmail,
        connection: 'Username-Password-Authentication',
        verify_email: true
      })
    })

    if (!res.ok) {
      const errorText = await res.text()
      throw new Error(
        `Failed to update user email. Status: ${res.status} - ${errorText}`
      )
    }
  }

  private async setAuthCookie({
    cookies,
    payload
  }: {
    cookies: Cookies
    payload: JWTPayload
  }) {
    const cookieValue = await jwt.sign(payload, this.sessionSecret)

    cookies.set(this.auth0CookieName, cookieValue, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: COOKIE_DURATION_SECONDS,
      path: '/'
    })
  }
}
