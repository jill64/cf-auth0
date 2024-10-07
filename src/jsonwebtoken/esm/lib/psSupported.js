import semver from 'semver'
import process from 'node:process'

export default semver.satisfies(process.version, '^6.12.0 || >=8.0.0')
