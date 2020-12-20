import {Command, flags} from '@oclif/command'
import {hostname} from 'os'
import open from 'open'
import {createInterface} from 'readline'
import {generateKeyPairSync, privateDecrypt, constants} from 'crypto'
import debug from 'debug'

const print = debug('discourse-api-key-generator')
const {publicKey, privateKey} = generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'pkcs1',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs1',
    format: 'pem',
  },
})

function buildUrl(site: string, applicationName: string): string {
  if (!site.startsWith('https://')) {
    throw new Error('The site URL should start with "https://"')
  } else if (site.endsWith('/')) {
    throw new Error('The site URL name should have no trailing slash')
  }
  const url = new URL(`${site}/user-api-key/new`)

  url.searchParams.append('application_name', applicationName)
  url.searchParams.append('client_id', hostname())
  url.searchParams.append('scopes', 'write')
  url.searchParams.append('public_key', publicKey)
  url.searchParams.append('nonce', '1')
  print(`redirect URL is ${url.href}`)
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
        'URL of Discourse to access. e.g. https://meta.discourse.org',
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
    const url = buildUrl(parsed.flags.url, parsed.flags.app)
    try {
      await open(url)
    } catch (error) {
      console.error(`Failed to launch browser. ${error.stack}`)
      process.exit(1)
    }

    const readline = createInterface({
      input: process.stdin,
      output: process.stdout,
    })
    readline.question(
      'Please input the encoded key displayed in the Discourse:',
      encodedKey => {
        const trim = encodedKey.trim().replace(/\s/g, '')
        print(`trimmed encoded key is ${trim}`)
        const decreptedKey = privateDecrypt(
          {
            key: privateKey,
            padding: constants.RSA_PKCS1_PADDING,
          },
          Buffer.from(trim, 'base64')
        )
        const json = decreptedKey.toString('ascii')
        print(`The decoded json is ${json}`)
        readline.close()

        console.info(`Done. The API key is ${JSON.parse(json).key}`)
        process.exit(0)
      }
    )
  }
}

export = DiscourseApiKeyGenerator
