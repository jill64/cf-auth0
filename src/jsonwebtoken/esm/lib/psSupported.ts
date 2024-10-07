import process from 'node:process'
import semver from 'semver'

export default semver.satisfies(process.version, '^6.12.0 || >=8.0.0')
