import process from 'node:process'
import semver from 'semver'

export default semver.satisfies(process.version, '>=16.9.0')
