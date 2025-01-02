import { auth } from '$lib/server/example.js'
import { redirect } from '@sveltejs/kit'

export const GET = (param) => {
  const url = auth.login(param)
  redirect(302, url)
}
