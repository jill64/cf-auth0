import semver from 'semver'
import process from 'node:process'

export default semver.satisfies(process.version, '>=15.7.0')
