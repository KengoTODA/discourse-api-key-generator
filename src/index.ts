import {Command, flags} from '@oclif/command'
import {createServer} from 'http'
import {hostname} from 'os'
import open from 'open'
import {parse} from 'url'
import {generateKeyPairSync, privateDecrypt} from 'crypto'

const {publicKey, privateKey} = generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem',
    cipher: 'aes-256-cbc',
    passphrase: 'top secret',
  },
})

const server = createServer((req, res) => {
  try {
    if (req.url === undefined) {
      throw new Error('No URL found form the given request')
    }

    const queryObject = parse(req.url, true).query
    let encodedKey = queryObject.payload
    if (encodedKey === undefined) {
      throw new Error('The response from discource has no payload')
    }
    if (Array.isArray(encodedKey)) {
      encodedKey = encodedKey.join()
    }
    console.debug(`encoded key is ${encodedKey}`)
    const decreptedKey = privateDecrypt(privateKey, Buffer.from(encodedKey))
    console.log(`Done. The API key is ${decreptedKey}.`)
    res.setHeader('Content-Type', 'text/plain')
    res.write(`Done. The API key is ${decreptedKey}.`)
  } finally {
    res.end()
  }
})

function buildUrl(port: number, host: string, applicationName: string): string {
  if (!host.startsWith('https://')) {
    throw new Error('The host name should start with "https://"')
  } else if (host.endsWith('/')) {
    throw new Error('The host name should have no trailing slash')
  }
  const redirectUrl = `http://localhost:${port}/callback`
  const url = new URL(`${host}/user-api-key/new`)

  url.searchParams.append('auth_redirect', redirectUrl)
  url.searchParams.append('application_name', applicationName)
  url.searchParams.append('client_id', hostname())
  url.searchParams.append('scopes', 'write')
  url.searchParams.append('public_key', publicKey)
  url.searchParams.append('nonce', '1')
  console.debug(`redirect URL is ${url.href}`)
  return url.href
}

class DiscourseApiKeyGenerator extends Command {
  static description = 'describe the command here'

  static flags = {
    version: flags.version({char: 'v'}),
    help: flags.help({char: 'h'}),
    url: flags.string({
      char: 'u',
      description:
        'URL of Discourse to access. e.g. https://meta.discourse.org/',
      required: true,
    }),
    app: flags.string({
      char: 'a',
      description: 'Name of your application.',
      required: true,
    }),
  }

  async run(): Promise<void> {
    const parsed = this.parse(DiscourseApiKeyGenerator)
    server.listen(0, async () => {
      const addressInfo = server.address()
      if (addressInfo === null || typeof addressInfo === 'string') {
        console.error(`Unexpected address info: ${addressInfo}`)
      } else {
        const port = addressInfo.port
        const url = buildUrl(port, parsed.flags.url, parsed.flags.app)
        try {
          await open(url)
        } catch (error) {
          console.error(`Failed to launch browser. ${error.stack}`)
        }
      }
    })
  }
}

export = DiscourseApiKeyGenerator
