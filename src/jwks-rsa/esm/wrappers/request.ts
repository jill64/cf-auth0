export default async (options: { uri: string; headers: Headers }) => {
  const res = await fetch(options.uri, {
    headers: options.headers
  })

  if (!res.ok) {
    const errorMsg =
      (res.body && (await res.text())) ||
      res.statusText ||
      `Http Error ${res.status}`

    throw Error(errorMsg)
  }

  return res.json()
}
