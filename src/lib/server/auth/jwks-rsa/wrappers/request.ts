export default async (uri: string) => {
  const res = await fetch(uri)

  if (!res.ok) {
    const errorMsg =
      (await res.text()) || res.statusText || `Http Error ${res.status}`

    throw Error(errorMsg)
  }

  return await res.json()
}
