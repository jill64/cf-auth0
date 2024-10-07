import ms from 'ms'

export default function (time: string | number, iat: number) {
  const timestamp = iat || Math.floor(Date.now() / 1000)

  if (typeof time === 'string') {
    var milliseconds = ms(time)
    if (typeof milliseconds === 'undefined') {
      return
    }
    return Math.floor(timestamp + milliseconds / 1000)
  } else if (typeof time === 'number') {
    return timestamp + time
  } else {
    return
  }
}
