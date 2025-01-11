import {
  AUTH0_CLIENT_ID,
  AUTH0_CLIENT_SECRET,
  AUTH0_DOMAIN,
  BASE_URL,
  SESSION_SECRET
} from '$env/static/private'
import { CfAuth0 } from '$lib'

export const auth = new CfAuth0({
  auth0ClientId: AUTH0_CLIENT_ID,
  auth0Domain: AUTH0_DOMAIN,
  auth0ClientSecret: AUTH0_CLIENT_SECRET,
  callbackPath: '/api/auth/callback',
  loginPath: '/api/auth/login',
  logoutPath: '/api/auth/logout',
  baseUrl: BASE_URL,
  isSvelteKit: true,
  sessionSecret: SESSION_SECRET
})
