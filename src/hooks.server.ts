import { hooks } from '@jill64/npm-demo-layout'
import { init } from '@jill64/sentry-sveltekit-cloudflare/server'

const { onHandle, onError } = init(
  'https://0d37137133a4b361c9a35546860fe68b@o4505814639312896.ingest.us.sentry.io/4508574807359488'
)

export const handle = onHandle(hooks)
export const handleError = onError()
