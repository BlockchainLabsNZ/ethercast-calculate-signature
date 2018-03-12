import {
  calculateMessageSignature,
  isValidSignature,
  SignatureVersion
} from '../src/calculate-signature'

const SIGNATURE_PATTERNS: { [v in SignatureVersion]: RegExp } = {
  [SignatureVersion.sha512]: /[a-f0-9]{128}/,
  [SignatureVersion.sha256]: /[a-f0-9]{64}/
}

describe('calculate-signature', () => {
  Object.keys(SignatureVersion).forEach((version: SignatureVersion) => {
    describe(`version: ${version}`, () => {
      ;['abc', '{"abc":"123"}'].forEach(example => {
        describe(`example: ${JSON.stringify(example)}`, () => {
          it('signature length', () => {
            expect(calculateMessageSignature(example, 'abc', version)).toMatch(
              SIGNATURE_PATTERNS[version]
            )
          })

          it(`works with matching secrets`, () => {
            expect(
              isValidSignature(
                example,
                'secret',
                calculateMessageSignature(example, 'secret', version),
                version
              )
            ).toEqual(true)
          })

          it(`fails with non-matching secrets`, () => {
            expect(
              isValidSignature(
                example,
                'secret1',
                calculateMessageSignature(example, 'secret2', version),
                version
              )
            ).toEqual(false)
          })
        })
      })
    })
  })
})
