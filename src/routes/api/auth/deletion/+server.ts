import { auth } from '$lib/server/example'
import { redirect } from '@sveltejs/kit'

export const GET = async () => {
  const url = await auth.delete()
  return redirect(302, url)
}
