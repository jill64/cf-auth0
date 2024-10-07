export default async (options) => {
  const res = await fetch(options.uri, {
    headers: options.headers
  })

  if (!res.ok) {
    const errorMsg =
      (await res.text()) ?? res.statusText ?? `Http Error ${res.status}`
    throw new Error({ errorMsg })
  }

  return await res.json()
}
