import { exec } from 'node:child_process'
import { mkdir, rm } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const repro = async (name: string, user: string, repo: string) => {
  const dest = path.join(__dirname, `../src/${name}/cjs`)

  await rm(dest, { recursive: true, force: true })
  await mkdir(dest, { recursive: true })

  console.log(`⏳ Cloning ${user}/${repo}...`)

  await promisify(exec)(
    `git clone https://github.com/${user}/${repo}.git --depth 1`,
    { cwd: dest }
  )

  console.log(`✅ Cloned ${user}/${repo}.`)
}

await Promise.allSettled([
  repro(
    'buffer-equal-constant-time',
    'salesforce',
    'buffer-equal-constant-time'
  ),
  repro('jws', 'auth0', 'node-jws'),
  repro('jsonwebtoken', 'auth0', 'node-jsonwebtoken'),
  repro('jwks-rsa', 'auth0', 'node-jwks-rsa'),
  repro('ecdsa-sig-formatter', 'Brightspace', 'node-ecdsa-sig-formatter'),
  repro('jwa', 'auth0', 'node-jwa'),
  repro('lru-memoizer', 'jfromaniello', 'lru-memoizer')
])
