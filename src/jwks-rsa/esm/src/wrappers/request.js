// @ts-expect-error TODO
export default async (options) => {
  // eslint-disable-next-line no-undef
  const res = await fetch(options.uri, {
    headers: options.headers
  })

  if (!res.ok) {
    const errorMsg =
      (await res.text()) ?? res.statusText ?? `Http Error ${res.status}`
    // @ts-expect-error TODO
    throw new Error({ errorMsg })
  }

  return await res.json()
}
