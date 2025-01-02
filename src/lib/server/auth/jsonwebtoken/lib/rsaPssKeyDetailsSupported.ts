import semver from 'semver'
import process from 'node:process'

export default semver.satisfies(process.version, '>=16.9.0')
