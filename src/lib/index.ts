import { getToken, verifyToken } from '$lib/server/auth/auth0'
import * as jwt from '$lib/server/auth/jsonwebtoken'
import type { Cookies } from '@sveltejs/kit'
import type { JWTPayload } from 'jose'
import crypto from 'node:crypto'

const COOKIE_DURATION_SECONDS = 60 * 60 * 24 * 7 // 1 week

export class CfAuth0 {
  private auth0ClientId
  private auth0ClientSecret
  private auth0Domain
  private baseUrl
  private auth0CookieName
  private sessionSecret
  private callbackPath
  private loginPath
  private isSvelteKit

  constructor({
    auth0CookieName = 'auth0',
    sessionSecret,
    auth0ClientId,
    auth0ClientSecret,
    auth0Domain,
    baseUrl,
    callbackPath,
    loginPath,
    isSvelteKit
  }: {
    auth0ClientId: string

    auth0ClientSecret: string

    /** @example 'example.us.auth0.com' */
    auth0Domain: string

    /** @example 'http://localhost:3000' */
    baseUrl: string

    /** @example '/api/auth/callback' */
    callbackPath: string

    /** @example '/api/auth/login' */
    loginPath: string

    auth0CookieName?: string
    sessionSecret: string
    isSvelteKit?: boolean
  }) {
    this.auth0ClientId = auth0ClientId
    this.auth0ClientSecret = auth0ClientSecret
    this.auth0Domain = auth0Domain
    this.baseUrl = baseUrl
    this.auth0CookieName = auth0CookieName
    this.sessionSecret = sessionSecret
    this.callbackPath = callbackPath
    this.loginPath = loginPath
    this.isSvelteKit = isSvelteKit
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
      const payload = await jwt.verify(cookie, this.sessionSecret)

      await this.setAuthCookie({
        cookies,
        payload
      })

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

    return `https://${this.auth0Domain}/authorize?${new URLSearchParams(
      query
    ).toString()}`
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

    return `https://${this.auth0Domain}/logout?client_id=${this.auth0ClientId}&returnTo=${returnUrl}`
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

    const token = await getToken({
      code,
      auth0_domain: this.auth0Domain,
      auth0_client_id: this.auth0ClientId,
      auth0_client_secret: this.auth0ClientSecret,
      redirect_uri: `${this.baseUrl}${this.callbackPath}`
    })

    const authUser = await verifyToken({
      token: token.id_token,
      jwksUri: `https://${this.auth0Domain}/.well-known/jwks.json`
    })

    await this.setAuthCookie({
      cookies,
      payload: authUser
    })

    cookies.delete('csrfState', { path: '/' })

    return returnUrl
  }

  private setAuthCookie = async ({
    cookies,
    payload
  }: {
    cookies: Cookies
    payload: JWTPayload
  }) => {
    const cookieValue = await jwt.sign(payload, this.sessionSecret)

    cookies.set(this.auth0CookieName, cookieValue, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: COOKIE_DURATION_SECONDS,
      path: '/'
    })
  }
}
