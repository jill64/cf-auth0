import { auth } from '$lib/server/example.js'
import { redirect } from '@sveltejs/kit'

export const GET = (param) => {
  const url = auth.logout(param)
  redirect(302, url)
}
