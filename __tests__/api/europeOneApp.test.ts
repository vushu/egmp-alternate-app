/**
 * Hyundai EU OneApp (CCI) WebView login flow tests.
 *
 * Exercises the new WebView-based login: the stored OAuth redirect is
 * exchanged for CCI tokens (fingerprint-gated route), then for a CCS token.
 * No network calls are made.
 */

import { installFetchMock } from '../helpers/fetchMock'
import { BluelinkEurope, getEuropeAuthUrls, hmacSha256Hex } from '@/src/api/regions/europe'
import { storeWebviewAuthResult } from '@/src/api/regions/europe'
import type { Config } from '@/src/config/types'

jest.mock('@/src/storage/secureStore', () => {
  const store: Record<string, string> = {}
  return {
    storageGet: jest.fn(async (k: string) => store[k] ?? null),
    storageSet: jest.fn(async (k: string, v: string) => {
      store[k] = v
    }),
    storageContains: jest.fn(async (k: string) => k in store),
    storageRemove: jest.fn(async (k: string) => {
      delete store[k]
    }),
    mockStore: store,
  }
})
jest.mock('@/src/storage/configStore', () => ({
  saveConfig: jest.fn().mockResolvedValue(undefined),
}))

const TEST_CONFIG: Config = {
  manufacturer: 'hyundai',
  auth: {
    username: '',
    password: '',
    pin: '1234',
    region: 'europe',
  },
  vin: 'KMXXXXXXXXXXXXXXX',
  tempType: 'C',
  distanceUnit: 'km',
  climateTempWarm: 21.5,
  climateTempCold: 19,
  climateSeatLevel: 'Off',
  mfaPreference: 'sms',
  carColor: 'white',
}

const cciTokenFixture = require('../fixtures/europe-cci-token.json')
const cciExchangeFixture = require('../fixtures/europe-cci-token-exchange.json')

// The storage mock persists across tests in a module-level store; clear it so
// each test starts without a cached session (forcing a fresh login).
beforeEach(() => {
  const store = require('@/src/storage/secureStore').mockStore as Record<string, string>
  for (const key of Object.keys(store)) delete store[key]
})

describe('Hyundai EU OneApp login', () => {
  let fetchMock: ReturnType<typeof installFetchMock>

  beforeEach(async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {})
    jest.spyOn(console, 'error').mockImplementation(() => {})
    fetchMock = installFetchMock([
      { pattern: /cci-api-eu\.hyundai\.com\/auth\/v1\/token\?code=/, response: cciTokenFixture },
      { pattern: /cci-api-eu\.hyundai\.com\/auth\/v1\/token-exchange/, response: cciExchangeFixture },
    ])
  })

  afterEach(() => {
    fetchMock.restore()
    jest.restoreAllMocks()
  })

  it('requests WebView login when no stored auth result exists', async () => {
    const bluelink = await BluelinkEurope.init(TEST_CONFIG, true)
    expect(bluelink.needRestart()).toBe(true)
  })

  it('exchanges the stored auth code for CCI and CCS tokens', async () => {
    await storeWebviewAuthResult('https://oneapp.hyundai.com/redirect?code=fixture-auth-code-123')
    const bluelink = await BluelinkEurope.init(TEST_CONFIG, true)

    expect(bluelink.needRestart()).toBe(false)
    expect(bluelink.loginFailed()).toBe(false)

    // Auth code exchanged on the fingerprint-gated CCI route
    const codeCalls = fetchMock.callsTo(/cci-api-eu\.hyundai\.com\/auth\/v1\/token\?code=/)
    expect(codeCalls.length).toBeGreaterThanOrEqual(1)
    const codeHeaders = codeCalls[0]!.init?.headers as Record<string, string>
    expect(codeHeaders['client-id']).toBe('com.hyundai.oneapp.eu')
    expect(codeHeaders['client-name']).toBe('HyundaiEU')
    expect(codeHeaders['X-Fingerprint']).toMatch(/^[0-9a-f]{64}$/)
    expect(codeHeaders['X-Timestamp']).toMatch(/^\d+$/)

    // CCS token exchange
    const exchangeCalls = fetchMock.callsTo(/cci-api-eu\.hyundai\.com\/auth\/v1\/token-exchange/)
    expect(exchangeCalls.length).toBeGreaterThanOrEqual(1)
    const exchangeHeaders = exchangeCalls[0]!.init?.headers as Record<string, string>
    expect(exchangeHeaders['authorization']).toBe('Bearer fixture-cci-access-token')
    expect(exchangeHeaders['Authentication']).toBe('fixture-cci-non-ccs-token')
    expect(exchangeHeaders['exchangeable-token']).toBe('fixture-cci-exchangeable-access')

    // Vehicle list still fetched through the legacy ccapi endpoints
    const vehicleCalls = fetchMock.callsTo(/\/api\/v1\/spa\/vehicles$/)
    expect(vehicleCalls.length).toBeGreaterThanOrEqual(1)
  })

  it('falls back to the legacy exchange route when the fingerprint gate rejects', async () => {
    await storeWebviewAuthResult('https://oneapp.hyundai.com/redirect?code=fixture-auth-code-123')
    fetchMock.restore()
    fetchMock = installFetchMock([
      { pattern: /cci-api-eu\.hyundai\.com\/auth\/v1\/token\?code=/, response: { code: 9036 }, status: 403 },
      { pattern: /cci-api-eu\.hyundai\.com\/domain\/api\/v1\/auth\/token\?code=/, response: cciTokenFixture },
      { pattern: /cci-api-eu\.hyundai\.com\/auth\/v1\/token-exchange/, response: { code: 9036 }, status: 403 },
      { pattern: /cci-api-eu\.hyundai\.com\/domain\/api\/v1\/auth\/token-exchange/, response: cciExchangeFixture },
    ])

    const bluelink = await BluelinkEurope.init(TEST_CONFIG, true)
    expect(bluelink.loginFailed()).toBe(false)

    const legacyCalls = fetchMock.callsTo(/cci-api-eu\.hyundai\.com\/domain\/api\/v1\/auth\/token\?code=/)
    expect(legacyCalls.length).toBeGreaterThanOrEqual(1)
    const legacyExchange = fetchMock.callsTo(/cci-api-eu\.hyundai\.com\/domain\/api\/v1\/auth\/token-exchange/)
    expect(legacyExchange.length).toBeGreaterThanOrEqual(1)
  })
})

describe('getEuropeAuthUrls', () => {
  it('returns OneApp URLs for Hyundai', () => {
    const urls = getEuropeAuthUrls('hyundai')
    expect(urls).not.toBeNull()
    expect(urls!.startUrl).toContain('idpconnect-eu.hyundai.com')
    expect(urls!.startUrl).toContain('client_id=4f4953b5-02e1-4dbc-8599-87e983ee1be5')
    expect(urls!.startUrl).toContain('redirect_uri=https://oneapp.hyundai.com/redirect')
    expect(urls!.callbackUrl).toBe('https://oneapp.hyundai.com/redirect')
  })

  it('returns OneApp URLs for Kia', () => {
    const urls = getEuropeAuthUrls('kia')
    expect(urls).not.toBeNull()
    expect(urls!.startUrl).toContain('idpconnect-eu.kia.com')
    expect(urls!.callbackUrl).toBe('https://oneapp.kia.com/redirect')
  })

  it('returns null for unsupported manufacturers', () => {
    expect(getEuropeAuthUrls('genesis')).toBeNull()
  })
})

describe('hmacSha256Hex', () => {
  it('matches the RFC 4231 test vector', () => {
    expect(hmacSha256Hex('key', 'The quick brown fox jumps over the lazy dog')).toBe(
      'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8',
    )
  })

  it('hashes keys longer than the block size', () => {
    expect(hmacSha256Hex('k'.repeat(100), 'msg')).toBe(
      'bd56a1782c2830e8abc6ed866a57a1230661e650b84c62f7ee3accc5fa5af491',
    )
  })
})
