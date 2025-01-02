import { auth } from '$lib/server/example.js'
import { redirect } from '@sveltejs/kit'

export const GET = async (param) => {
  const url = await auth.callback(param)
  redirect(302, url)
}
