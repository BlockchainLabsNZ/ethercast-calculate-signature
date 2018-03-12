import { createHmac } from 'crypto'

export enum SignatureVersion {
  sha256 = 'sha256',
  sha512 = 'sha512'
}

/**
 * Calculate the signature for a message body using the subscription secret
 * @param {string} messageBody body of the message
 * @param {string} subscriptionSecret secret of the subscription
 * @param version the version of the message signature (optional, defaults to sha512)
 * @returns {string} the message signature
 */
export function calculateMessageSignature(
  messageBody: string,
  subscriptionSecret: string,
  version: SignatureVersion = SignatureVersion.sha512
): string {
  const hmac = createHmac(version, subscriptionSecret)
  hmac.update(messageBody)
  return hmac.digest('hex')
}

/**
 * Returns true if the message body and secret return a matching signature
 * @param {string} messageBody body of the message
 * @param {string} subscriptionSecret subscription secret
 * @param signature
 * @param version the version of the message signature (optional, defaults to sha512)
 * @returns {boolean} true if the message is valid, false otherwise
 */
export function isValidSignature(
  messageBody: string,
  subscriptionSecret: string,
  signature: string,
  version: SignatureVersion = SignatureVersion.sha512
): boolean {
  return (
    signature ===
    calculateMessageSignature(messageBody, subscriptionSecret, version)
  )
}
