import { auth } from '$lib/server/example'
import { hooks } from '@jill64/npm-demo-layout'
import { init } from '@jill64/sentry-sveltekit-cloudflare/server'
import { redirect } from '@sveltejs/kit'
import { sequence } from '@sveltejs/kit/hooks'

const { onHandle, onError } = init(
  'https://0d37137133a4b361c9a35546860fe68b@o4505814639312896.ingest.us.sentry.io/4508574807359488'
)

export const handle = onHandle(
  sequence(hooks, async ({ resolve, event }) => {
    if (event.url.pathname.startsWith('/api/auth')) {
      return resolve(event)
    }

    const result = await auth.auth(event)

    if (typeof result === 'string') {
      redirect(302, result)
    }

    console.log('result', result)

    return resolve(event)
  })
)
export const handleError = onError()
