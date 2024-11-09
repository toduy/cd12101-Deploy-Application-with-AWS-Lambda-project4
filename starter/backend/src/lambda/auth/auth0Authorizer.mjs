import jsonwebtoken from 'jsonwebtoken'
import { createLogger } from '../../utils/logger.mjs'

const logger = createLogger('auth')

const cer = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJPnyrKwRATsmIMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi1qYzFmbTFjMzc4aWVkZHF6LnVzLmF1dGgwLmNvbTAeFw0yNDExMDUy
MzMzNDVaFw0zODA3MTUyMzMzNDVaMCwxKjAoBgNVBAMTIWRldi1qYzFmbTFjMzc4
aWVkZHF6LnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBANDEjsGzPSQbSH2qhftG3uq/rr9VENL7U+Pmvs/bk4p3AarPSRFr9L+8Z/Ex
tIvUgZenydPYGwoqv2vxl+xF2cp9EIMgyNYBWDeFEvX6EykO535njGf+JAzqqvg0
90Vd2xsVwHkYTSYi1/ttO26kSjkbjgJUrob4mA0N5yH72yzLH0kdoy35ujeDX230
A6BasxCQc/Ji56Dn0vD9e7RKXgdR/Lf+2O+n978LoCgosHFVptlp7h8ihy7J+8bV
z/opFy0B8Adwdo7nC+5woBNEyrmHHYC56LYb94ODsnoFK5SDQo5IhHK07Xh72wNl
PlS3Oo/Dmz3bSoNDPqTvsJq66l0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUm3BR8DDHoLEEqaI4KzEYZEcnV2MwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQBNQOEd59I98xPVFCPzmZ6CkrjEC7Xl1Lc709Lk5nOc
NbW4qG4uMbn2Scc6TY1XtIwEEISG0V+5BN81ZDU4EjBpmTGsZ2O3K2pN3W9uNWkw
/oPgq+ostFE2MVGVADMCaobah7unvvnCoRR5CS1MxT1VAKzsp0tNbgylACuX+tFx
LkIsQTGdmRZEEKI72hP7D/9sNIYjaVQvMOQhZD0VnXybDmP3hAxEihmAR/3SQQI/
uktgWrrOhjV7r7bOgP9YYReCEeltnJLXcV+iaD+DyNskIwL2+YStUmLllSq7tCHC
HhjqQyv1X54jyaxjTbhSX5sjb0+Vj/gqVicjrOGZHt96
-----END CERTIFICATE-----`

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)

  return jsonwebtoken.verify(token, cer, { algorithms: ['RS256'] });
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
