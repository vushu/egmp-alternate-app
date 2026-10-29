// Europe region — based on bluelinky's EuropeanBrandAuthStrategy + EuropeanController.
// Hyundai and Kia both use WebView-based OAuth against the OneApp (CCI) identity system.
// Hyundai EU previously used a user-provided refresh token; Hyundai's IDP now blocks
// that flow, so both brands log in through the OneApp WebView + CCI token exchange.

import {
  Bluelink,
  BluelinkTokens,
  BluelinkCar,
  BluelinkStatus,
  ClimateRequest,
  ChargeLimit,
  Location,
  DEFAULT_STATUS_CHECK_INTERVAL,
  MAX_COMPLETION_POLLS,
  CHARGE_COMPLETION_POLLS,
  isNotEmptyObject,
  parseUrlParams,
} from '../base'
import { Config } from '../../config/types'
import { storageGet, storageSet, storageRemove, storageContains } from '../../storage/secureStore'
import { saveConfig } from '../../storage/configStore'

interface ControlToken {
  expiry: number
  token: string
}

interface APIConfig {
  apiDomain: string
  newApiDomain?: string
  apiPort: number
  appId: string
  authCfb: string
  authBasic: string
  authHost: string
  authClientSecret?: string
  clientId: string
  pushType: string
  // OneApp (CCI) identity — used by the WebView login flow
  cciApiDomain?: string
  cciPackageId?: string
  cciClientName?: string
  cciFingerprintKeys?: [string, string, string]
}

const API_CONFIG: Record<string, APIConfig> = {
  hyundai: {
    apiDomain: 'prd.eu-ccapi.hyundai.com',
    newApiDomain: 'cci-api-eu.hyundai.com',
    apiPort: 8080,
    appId: '014d2225-8495-4735-812d-2616334fd15d',
    authCfb: 'RFtoRq/vDXJmRndoZaZQyfOot7OrIqGVFj96iY2WL3yyH5Z/pUvlUhqmCxD2t+D65SQ=',
    authBasic:
      'Basic NmQ0NzdjMzgtM2NhNC00Y2YzLTk1NTctMmExOTI5YTk0NjU0OktVeTQ5WHhQekxwTHVvSzB4aEJDNzdXNlZYaG10UVI5aVFobUlGampvWTRJcHhzVg==',
    authHost: 'idpconnect-eu.hyundai.com',
    clientId: '6d477c38-3ca4-4cf3-9557-2a1929a94654',
    authClientSecret: 'KUy49XxPzLpLuoK0xhBC77W6VXhmtQR9iQhmIFjjoY4IpxsV',
    pushType: 'GCM',
    cciApiDomain: 'cci-api-eu.hyundai.com',
    cciPackageId: 'com.hyundai.oneapp.eu',
    cciClientName: 'HyundaiEU',
    cciFingerprintKeys: ['OsZDfDuCyVX', 'yfqjCoA2JbX', '2MrLpGwNBC'],
  },
  kia: {
    apiDomain: 'prd.eu-ccapi.kia.com',
    newApiDomain: 'cci-api-eu.kia.com',
    apiPort: 8080,
    appId: 'a2b8469b-30a3-4361-8e13-6fceea8fbe74',
    authCfb: 'wLTVxwidmH8CfJYBWSnHD6E0huk0ozdiuygB4hLkM5XCgzAL1Dk5sE36d/bx5PFMbZs=',
    authBasic: 'Basic ZmRjODVjMDAtMGEyZi00YzY0LWJjYjQtMmNmYjE1MDA3MzBhOnNlY3JldA==',
    authHost: 'idpconnect-eu.kia.com',
    clientId: 'fdc85c00-0a2f-4c64-bcb4-2cfb1500730a',
    pushType: 'APNS',
  },
}

const WEBVIEW_AUTH_STORE_KEY = 'egmp-bl-webview-auth'
const WEBVIEW_AUTH_MAX_AGE_MS = 5 * 60 * 1000

// Synchronous HMAC-SHA256 (hex digest) for the CCI X-Fingerprint signature.
// Uses a compact pure-JS SHA-256 implementation so it works on native and web
// without async crypto APIs.
export function hmacSha256Hex(key: string, message: string): string {
  const sha256 = (bytes: number[]): number[] => {
    const K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]
    const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    const w = new Array(64).fill(0)

    const padded = [...bytes]
    const bitLen = bytes.length * 8
    padded.push(0x80)
    while (padded.length % 64 !== 56) padded.push(0)
    // 64-bit big-endian length (high 4 bytes are zero for realistic sizes)
    padded.push(0, 0, 0, 0, (bitLen >>> 24) & 0xff, (bitLen >>> 16) & 0xff, (bitLen >>> 8) & 0xff, bitLen & 0xff)

    const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n))
    for (let i = 0; i < padded.length; i += 64) {
      for (let t = 0; t < 16; t++) {
        w[t] =
          (padded[i + t * 4]! << 24) | (padded[i + t * 4 + 1]! << 16) | (padded[i + t * 4 + 2]! << 8) | padded[i + t * 4 + 3]!
      }
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(w[t - 15]!, 7) ^ rotr(w[t - 15]!, 18) ^ (w[t - 15]! >>> 3)
        const s1 = rotr(w[t - 2]!, 17) ^ rotr(w[t - 2]!, 19) ^ (w[t - 2]! >>> 10)
        w[t] = (w[t - 16]! + s0 + w[t - 7]! + s1) >>> 0
      }
      let [a, b, c, d, e, f, g, h] = H
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        const ch = (e & f) ^ (~e & g)
        const temp1 = (h + S1 + ch + K[t]! + w[t]!) >>> 0
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        const maj = (a & b) ^ (a & c) ^ (b & c)
        const temp2 = (S0 + maj) >>> 0
        h = g
        g = f
        f = e
        e = (d + temp1) >>> 0
        d = c
        c = b
        b = a
        a = (temp1 + temp2) >>> 0
      }
      H[0] = (H[0]! + a) >>> 0
      H[1] = (H[1]! + b) >>> 0
      H[2] = (H[2]! + c) >>> 0
      H[3] = (H[3]! + d) >>> 0
      H[4] = (H[4]! + e) >>> 0
      H[5] = (H[5]! + f) >>> 0
      H[6] = (H[6]! + g) >>> 0
      H[7] = (H[7]! + h) >>> 0
    }
    const out: number[] = []
    for (const word of H) {
      out.push((word >>> 24) & 0xff, (word >>> 16) & 0xff, (word >>> 8) & 0xff, word & 0xff)
    }
    return out
  }

  const strBytes = (s: string): number[] => Array.from(new TextEncoder().encode(s))

  // HMAC per RFC 2104: keys longer than the block size are hashed first
  let keyBytes = strBytes(key)
  if (keyBytes.length > 64) keyBytes = sha256(keyBytes)
  while (keyBytes.length < 64) keyBytes.push(0)

  const inner = keyBytes.map((b, i) => b ^ 0x36)
  const outer = keyBytes.map((b, i) => b ^ 0x5c)
  const innerHash = sha256([...inner, ...strBytes(message)])
  const mac = sha256([...outer, ...innerHash])
  return mac.map((b) => b.toString(16).padStart(2, '0')).join('')
}

// Auth URLs for WebView-based login (OneApp flow for both Hyundai and Kia EU).
export interface EuropeAuthUrls {
  startUrl: string
  callbackUrl: string
}

export function getEuropeAuthUrls(manufacturer: string): EuropeAuthUrls | null {
  const cfg = API_CONFIG[manufacturer]
  if (!cfg) return null

  if (manufacturer === 'kia') {
    return {
      startUrl:
        `https://${cfg.authHost}/auth/api/v2/user/oauth2/authorize?` +
        [
          'client_id=01b36c86-79e8-486c-8009-15f2ad88d670',
          'redirect_uri=https://oneapp.kia.com/redirect',
          'response_type=code',
          'scope=account.token.transfer%20account.id.generate%20account.puid.userinfos%20account.userinfo%20read%20account.userinfos%20puid%20email%20name%20mobileNum%20birthdate%20lang%20country%20signUpDate%20gender%20nationInfo%20certProfile%20offline',
          'state=hmgoneapp',
          'ui_locales=en-GB',
        ].join('&'),
      callbackUrl: 'https://oneapp.kia.com/redirect',
    }
  }

  if (manufacturer === 'hyundai') {
    return {
      startUrl:
        `https://${cfg.authHost}/auth/api/v2/user/oauth2/authorize?` +
        [
          'client_id=4f4953b5-02e1-4dbc-8599-87e983ee1be5',
          'redirect_uri=https://oneapp.hyundai.com/redirect',
          'response_type=code',
          'state=ccsp',
          'lang=en',
          'country=de',
        ].join('&'),
      callbackUrl: 'https://oneapp.hyundai.com/redirect',
    }
  }

  return null
}

// Store the OAuth redirect URL after the WebView intercepts it
export async function storeWebviewAuthResult(redirectUrl: string) {
  await storageSet(WEBVIEW_AUTH_STORE_KEY, JSON.stringify({ redirectUrl, timestamp: Date.now() }))
}

export async function getStoredWebviewAuthResult(): Promise<string | null> {
  if (!(await storageContains(WEBVIEW_AUTH_STORE_KEY))) return null
  try {
    const raw = await storageGet(WEBVIEW_AUTH_STORE_KEY)
    if (!raw) return null
    const data = JSON.parse(raw)
    if (Date.now() - data.timestamp > WEBVIEW_AUTH_MAX_AGE_MS) {
      await clearStoredWebviewAuthResult()
      return null
    }
    return data.redirectUrl
  } catch {
    await clearStoredWebviewAuthResult()
    return null
  }
}

export async function clearStoredWebviewAuthResult() {
  if (await storageContains(WEBVIEW_AUTH_STORE_KEY)) {
    await storageRemove(WEBVIEW_AUTH_STORE_KEY)
  }
}

export class BluelinkEurope extends Bluelink {
  private lang = 'en'
  private apiConfig: APIConfig
  private controlToken: ControlToken | undefined
  private europeccs2: number | undefined
  private additionalAuthHeaders: Record<string, string>

  constructor(config: Config, statusCheckInterval?: number) {
    super(config)
    this.distanceUnit = config.distanceUnit
    if (!(config.manufacturer in API_CONFIG)) {
      throw Error(`Manufacturer ${config.manufacturer} not supported in Europe`)
    }
    this.apiConfig = API_CONFIG[config.manufacturer]!
    this.apiDomain = `https://${this.apiConfig.apiDomain}:${this.apiConfig.apiPort}`
    this.statusCheckInterval = statusCheckInterval || DEFAULT_STATUS_CHECK_INTERVAL
    this.additionalHeaders = {
      'User-Agent': 'okhttp/3.14.9',
      offset: this.getTimeZone().slice(0, 3),
      'ccsp-service-id': this.apiConfig.clientId,
      'ccsp-application-id': this.apiConfig.appId,
    }
    this.additionalAuthHeaders = {
      'client-id': 'com.kia.oneapp.eu',
      'client-name': 'Kia',
      'client-os-code': 'AOS',
      'client-os-version': '36',
      'client-version': '1.0.13',
      'User-Agent': 'Ktor client',
      'Accept-Language': 'en-GB',
      'Accept-Charset': 'UTF-8',
      Accept: 'application/json',
      timezone: this.getTimeZoneFull(),
      locale: 'GB',
    }
    this.authIdHeader = 'ccsp-device-id'
    this.authHeader = 'Authorization'
    this.controlToken = undefined
    this.europeccs2 = undefined
  }

  static async init(config: Config, refreshAuth: boolean, statusCheckInterval?: number) {
    const obj = new BluelinkEurope(config, statusCheckInterval)
    await obj.superInit(config, refreshAuth)
    return obj
  }

  private getCCS2Header(): string {
    return typeof this.europeccs2 !== 'undefined'
      ? this.europeccs2.toString()
      : this.cache?.car.europeccs2
        ? this.cache.car.europeccs2.toString()
        : '0'
  }

  private isCCS2(): boolean {
    const val = this.europeccs2 ?? this.cache?.car.europeccs2
    return typeof val === 'number' && val > 0
  }

  private requestResponseValid(resp: Record<string, any>, _data: Record<string, any>): { valid: boolean; retry: boolean } {
    if (Object.hasOwn(resp, 'statusCode') && (resp.statusCode === 200 || resp.statusCode === 204 || resp.statusCode === 302)) {
      return { valid: true, retry: false }
    }
    return { valid: false, retry: true }
  }

  protected async login(): Promise<BluelinkTokens | undefined> {
    if (this.config.manufacturer !== 'hyundai') {
      // Reset session for Kia
      await this.request({
        url: `${this.apiDomain}/api/v1/user/oauth2/authorize?response_type=code&state=test&client_id=${this.apiConfig.clientId}&redirect_uri=${this.apiDomain}/api/v1/user/oauth2/redirect&lang=${this.lang}`,
        noAuth: true,
        notJSON: true,
        validResponseFunction: this.requestResponseValid.bind(this),
      })
    }
    return this.config.manufacturer === 'kia' ? await this.KiaLogin() : await this.HyundaiLogin()
  }

  protected async HyundaiLogin(): Promise<BluelinkTokens | undefined> {
    // Legacy refresh-token flow: still honoured when the user has a working
    // token, but Hyundai's IDP now rejects most of these (403 / invalid grant),
    // so the primary path is the OneApp WebView login below.
    if (this.config.auth.refreshToken && this.config.auth.refreshToken !== 'DEMO') {
      console.log('[Europe] Trying provided refresh token for initial login')
      const tokens = await this.refreshHyundaiToken(this.config.auth.refreshToken)
      if (tokens) return tokens
      console.log('[Europe] Refresh token rejected — falling back to WebView login')
    }

    // OneApp WebView flow (same shape as Kia): the user logs in inside the
    // WebView, the redirect URL with the auth code is stored, then exchanged
    // for CCI tokens on the next connect attempt.
    const storedRedirect = await getStoredWebviewAuthResult()
    if (!storedRedirect) {
      console.log('[Europe Hyundai] No WebView auth result — login required')
      this.loginRequiredWebview = true
      return undefined
    }
    await clearStoredWebviewAuthResult()

    const codeParams = parseUrlParams(storedRedirect)
    const code = codeParams['code']
    if (!code) {
      console.error('[Europe Hyundai] Failed to extract code from redirect', storedRedirect)
      this.loginRequiredWebview = true
      return undefined
    }

    return await this.exchangeOneAppCode(code)
  }

  // Exchange a OneApp OAuth authorization code for CCI tokens, then for a CCS
  // access token. Mirrors the flow the official Hyundai/Kia apps use:
  //   POST cci-api-eu.../auth/v1/token?code=...  (fingerprint-gated)
  //   POST cci-api-eu.../auth/v1/token-exchange?serviceType=CCS
  // Falls back to the legacy domain/api routes when the fingerprint gate is
  // not enforced.
  private async exchangeOneAppCode(code: string): Promise<BluelinkTokens | undefined> {
    const cciDomain = this.apiConfig.cciApiDomain
    if (!cciDomain) {
      console.error('[Europe] OneApp CCI domain not configured for this manufacturer')
      return undefined
    }

    const deviceId = this.generateUUID()
    const fpHeaders = this.buildCciFingerprintHeaders(deviceId)

    // Step 1: exchange the auth code for the CCI token set
    const respTokens = await this.request({
      url: `https://${cciDomain}/auth/v1/token?code=${code}`,
      method: 'POST',
      noAuth: true,
      noRetry: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: fpHeaders,
    })

    let tokensJson = respTokens.json
    if (!this.requestResponseValid(respTokens.resp, tokensJson).valid) {
      // Fallback: legacy unsigned domain/api exchange
      console.log('[Europe] Fingerprint-gated token exchange failed — trying legacy route')
      const legacy = await this.request({
        url: `https://${cciDomain}/domain/api/v1/auth/token?code=${code}`,
        method: 'POST',
        noAuth: true,
        disableAdditionalHeaders: true,
        validResponseFunction: this.requestResponseValid.bind(this),
        headers: this.buildCciLegacyHeaders(deviceId),
      })
      if (!this.requestResponseValid(legacy.resp, legacy.json).valid) {
        throw Error(`Failed to exchange auth code: ${JSON.stringify(legacy.resp)}`)
      }
      tokensJson = legacy.json
    }

    if (!tokensJson.accessToken) {
      console.error('[Europe] CCI token exchange returned no accessToken')
      return undefined
    }

    const tokens: BluelinkTokens = {
      accessToken: '',
      refreshToken: '',
      expiry: Math.floor(Date.now() / 1000) + Number(tokensJson.expiresIn ?? 3600),
      authId: deviceId,
      additionalTokens: {
        access: tokensJson.accessToken,
        refresh: tokensJson.refreshToken,
        exchangeableAccess: tokensJson.exchangeableAccessToken,
        exchangeableRefresh: tokensJson.exchangeableRefreshToken,
        nonCcsToken: tokensJson.nonCcsToken,
        nonCcsRefreshToken: tokensJson.nonCcsRefreshToken,
        idToken: tokensJson.idToken,
      },
    }

    return await this.cciTokenExchange(tokens, deviceId)
  }

  // Exchange the CCI access token for a CCS token accepted by the legacy
  // ccapi:8080 vehicle endpoints this app uses.
  private async cciTokenExchange(tokens: BluelinkTokens, deviceId: string): Promise<BluelinkTokens | undefined> {
    if (!tokens.additionalTokens || !isNotEmptyObject(tokens.additionalTokens)) return undefined
    const cciDomain = this.apiConfig.cciApiDomain!

    const fpHeaders = this.buildCciFingerprintHeaders(deviceId)
    fpHeaders['authorization'] = `Bearer ${tokens.additionalTokens['access']}`
    fpHeaders['Authentication'] = tokens.additionalTokens['nonCcsToken'] ?? ''
    if (tokens.additionalTokens['exchangeableAccess']) {
      fpHeaders['exchangeable-token'] = tokens.additionalTokens['exchangeableAccess']
      fpHeaders['non-ccs-token'] = tokens.additionalTokens['nonCcsToken'] ?? ''
    }

    const respToken = await this.request({
      url: `https://${cciDomain}/auth/v1/token-exchange?serviceType=CCS`,
      method: 'POST',
      noAuth: true,
      noRetry: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: fpHeaders,
    })

    if (this.requestResponseValid(respToken.resp, respToken.json).valid && respToken.json.accessToken) {
      tokens.accessToken = `Bearer ${respToken.json.accessToken}`
      return tokens
    }

    // Fallback: legacy unsigned domain/api exchange
    console.log('[Europe] Fingerprint-gated CCS exchange failed — trying legacy route')
    const legacyHeaders = this.buildCciLegacyHeaders(deviceId, {
      cciAccess: tokens.additionalTokens['access'],
      nonCcsToken: tokens.additionalTokens['nonCcsToken'],
      exchangeable: tokens.additionalTokens['exchangeableAccess'],
    })
    const legacy = await this.request({
      url: `https://${cciDomain}/domain/api/v1/auth/token-exchange?serviceType=CCS`,
      method: 'POST',
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: legacyHeaders,
    })

    if (this.requestResponseValid(legacy.resp, legacy.json).valid && legacy.json.accessToken) {
      tokens.accessToken = `Bearer ${legacy.json.accessToken}`
      return tokens
    }
    return undefined
  }

  // Build the signed header set for the fingerprint-gated CCI auth endpoints.
  // The X-Fingerprint is an HMAC-SHA256 over the client identity plus
  // app-embedded constants (recovered from the OneApp Android build).
  private buildCciFingerprintHeaders(deviceId: string): Record<string, string> {
    const keys = this.apiConfig.cciFingerprintKeys!
    const identityHeaders: Record<string, string> = {
      'client-id': this.apiConfig.cciPackageId!,
      'client-name': this.apiConfig.cciClientName!,
      'client-version': '1.4.0',
      'client-os-code': 'android',
      'client-os-version': '14',
      'client-device-id': deviceId,
      'client-device-model': 'SM-S918B',
      'client-notification-provider-type': 'FCM',
      locale: 'EN',
      timezone: this.getTimeZoneFull(),
      'App-Request-Id': `${this.genRanHex(24).toUpperCase()}_${deviceId.replace(/-/g, '')}_AOS`,
      'X-Brand': this.config.manufacturer.charAt(0).toUpperCase() + this.config.manufacturer.slice(1),
      'X-Region': 'eu',
      'User-Agent': 'okhttp/4.12.0',
      Accept: '*/*',
      'Accept-Language': 'en',
    }

    const identity =
      identityHeaders['client-id'] +
      identityHeaders['client-name'] +
      identityHeaders['client-version'] +
      identityHeaders['client-os-code']
    const timestamp = Date.now().toString()
    const message = identity + identityHeaders['client-os-version'] + timestamp
    const key = identity + keys.join('')

    // HMAC-SHA256 via Web Crypto (async at call time is awkward here; the
    // base class request() is sync-header, so compute with a small sync
    // implementation over TextEncoder bytes).
    const fingerprint = hmacSha256Hex(key, message)
    return {
      ...identityHeaders,
      'X-Timestamp': timestamp,
      'X-Fingerprint': fingerprint,
    }
  }

  // Unsigned header set for the legacy domain/api CCI routes.
  private buildCciLegacyHeaders(
    deviceId: string,
    auth?: { cciAccess?: string; nonCcsToken?: string; exchangeable?: string },
  ): Record<string, string> {
    const headers: Record<string, string> = {
      'client-id': this.apiConfig.cciPackageId!,
      'client-name': this.apiConfig.cciClientName!,
      'client-version': '1.4.0',
      'client-os-code': 'android',
      'client-os-version': '14',
      'client-device-id': deviceId,
      'client-device-model': 'SM-S918B',
      'client-notification-provider-type': 'FCM',
      locale: 'EN',
      timezone: this.getTimeZoneFull(),
      Accept: 'application/json',
      'Accept-Language': 'en',
      'User-Agent': 'okhttp/4.12.0',
      'Content-Length': '0',
    }
    if (auth?.nonCcsToken) headers['Authentication'] = auth.nonCcsToken
    if (auth?.cciAccess) headers['authorization'] = `Bearer ${auth.cciAccess}`
    if (auth?.exchangeable) {
      headers['exchangeable-token'] = auth.exchangeable
      headers['non-ccs-token'] = auth.nonCcsToken ?? ''
    }
    return headers
  }

  private async refreshHyundaiToken(refreshToken: string): Promise<BluelinkTokens | undefined> {
    const resp = await this.request({
      url: `https://${this.apiConfig.authHost}/auth/api/v2/user/oauth2/token`,
      data: [
        'grant_type=refresh_token',
        `refresh_token=${refreshToken}`,
        `client_id=${this.apiConfig.clientId}`,
        `client_secret=${this.apiConfig.authClientSecret}`,
      ].join('&'),
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })

    if (this.requestResponseValid(resp.resp, resp.json).valid) {
      const newRefreshToken = resp.json.refresh_token || refreshToken
      // Persist rotated refresh token back to config for resilience
      if (this.config.auth.refreshToken && newRefreshToken !== this.config.auth.refreshToken) {
        this.config.auth.refreshToken = newRefreshToken
        saveConfig(this.config).catch(() => {})
      }
      // Reuse cached deviceId on refresh; only fetch a new one on initial login
      let authId = this.cache?.token?.authId
      if (!authId) {
        console.log('[Europe] No cached deviceId, fetching new one via notifications/register')
        authId = await this.getDeviceId()
        if (!authId) {
          console.error('[Europe] Failed to obtain deviceId — commands will fail until reconnect')
        }
      }
      return {
        accessToken: `Bearer ${resp.json.access_token}`,
        refreshToken: newRefreshToken,
        expiry: Math.floor(Date.now() / 1000) + Number(resp.json.expires_in),
        authId,
      }
    }
    return undefined
  }

  protected async KiaLogin(): Promise<BluelinkTokens | undefined> {
    const storedRedirect = await getStoredWebviewAuthResult()
    if (!storedRedirect) {
      this.loginRequiredWebview = true
      return undefined
    }
    await clearStoredWebviewAuthResult()

    const codeParams = parseUrlParams(storedRedirect)
    const code = codeParams['code']
    if (!code) {
      console.error('[Europe Kia] Failed to extract code from redirect', storedRedirect)
      return undefined
    }

    const respTokens = await this.request({
      url: `https://${this.apiConfig.newApiDomain}/domain/api/v1/auth/token?code=${code}`,
      method: 'POST',
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: {
        ...this.additionalAuthHeaders,
        'app-request-id': this.generateUUID(),
      },
    })

    if (!this.requestResponseValid(respTokens.resp, respTokens.json).valid) {
      throw Error(`Failed to login (Kia): ${JSON.stringify(respTokens.resp)}`)
    }

    const tokens: BluelinkTokens = {
      accessToken: '',
      refreshToken: '',
      expiry: Math.floor(Date.now() / 1000) + Number(respTokens.json.expiresIn),
      authId: await this.getDeviceId(),
      additionalTokens: {
        access: respTokens.json.accessToken,
        refresh: respTokens.json.refreshToken,
        exchangeableAccess: respTokens.json.exchangeableAccessToken,
        exchangeableRefresh: respTokens.json.exchangeableRefreshToken,
        nonCcsToken: respTokens.json.nonCcsToken,
        nonCcsRefreshToken: respTokens.json.nonCcsRefreshToken,
        idToken: respTokens.json.idToken,
      },
    }

    await this.KiaDeviceRegistration(tokens)
    await this.initKiaSession(tokens)
    return await this.tokenExchange(tokens)
  }

  protected async KiaDeviceRegistration(tokens: BluelinkTokens): Promise<boolean | undefined> {
    if (!tokens?.additionalTokens || !isNotEmptyObject(tokens.additionalTokens)) return undefined

    const resp = await this.request({
      url: `https://${this.apiConfig.newApiDomain}/domain/api/v1/notifications/bases/devices`,
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      data: JSON.stringify({
        appToken: `${this.genRanHex(22)}:${this.genRanHex(44)}_${this.genRanHex(11)}_${this.genRanHex(62)}`,
        deviceToken: this.generateUUID(),
        providerType: 'AOS',
        deviceModel: 'sdk_gphone64_arm64',
        deviceOsVer: '36',
        deviceAppVer: '1.0.11',
      }),
      headers: {
        ...this.additionalAuthHeaders,
        'app-request-id': this.generateUUID(),
        Authentication: tokens.additionalTokens['idToken'] ?? '',
        Authorization: `Bearer ${tokens.additionalTokens['access'] ?? ''}`,
        'exchangeable-token': tokens.additionalTokens['exchangeableAccess'] ?? '',
        'non-ccs-token': tokens.additionalTokens['nonCcsToken'] ?? '',
      },
    })

    if (!this.requestResponseValid(resp.resp, resp.json).valid) return undefined

    const deviceId = resp.json.deviceId
    await this.request({
      url: `https://${this.apiConfig.newApiDomain}/domain/api/v1/notifications/settings/preferences/language`,
      method: 'PUT',
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      data: JSON.stringify({ deviceId, countryCd: 'GB', langCd: 'en' }),
      headers: {
        ...this.additionalAuthHeaders,
        'app-request-id': this.generateUUID(),
        Authentication: tokens.additionalTokens['idToken'] ?? '',
        Authorization: `Bearer ${tokens.additionalTokens['access'] ?? ''}`,
        'exchangeable-token': tokens.additionalTokens['exchangeableAccess'] ?? '',
        'non-ccs-token': tokens.additionalTokens['nonCcsToken'] ?? '',
      },
    })

    return true
  }

  protected async initKiaSession(tokens: BluelinkTokens): Promise<boolean | undefined> {
    if (!tokens?.additionalTokens || !isNotEmptyObject(tokens.additionalTokens)) return undefined

    const headers = {
      ...this.additionalAuthHeaders,
      'app-request-id': this.generateUUID(),
      Authentication: tokens.additionalTokens['idToken'] ?? '',
      Authorization: `Bearer ${tokens.additionalTokens['access'] ?? ''}`,
      'exchangeable-token': tokens.additionalTokens['exchangeableAccess'] ?? '',
      'non-ccs-token': tokens.additionalTokens['nonCcsToken'] ?? '',
    }

    await this.request({
      url: `https://${this.apiConfig.newApiDomain}/oneapp/api/v1/initialize`,
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers,
    })

    await this.request({
      url: `https://${this.apiConfig.newApiDomain}/oneapp/api/v1/initialize/vehicle`,
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers,
    })

    return true
  }

  protected async tokenExchange(tokens: BluelinkTokens): Promise<BluelinkTokens | undefined> {
    if (!tokens?.additionalTokens || !isNotEmptyObject(tokens.additionalTokens)) return undefined

    const respToken = await this.request({
      url: `https://${this.apiConfig.newApiDomain}/domain/api/v1/auth/token-exchange?serviceType=CCS`,
      method: 'POST',
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: {
        ...this.additionalAuthHeaders,
        'app-request-id': this.generateUUID(),
        Authentication: tokens.additionalTokens['idToken'] ?? '',
        Authorization: `Bearer ${tokens.additionalTokens['access'] ?? ''}`,
        'exchangeable-token': tokens.additionalTokens['exchangeableAccess'] ?? '',
        'non-ccs-token': tokens.additionalTokens['nonCcsToken'] ?? '',
      },
    })

    if (!this.requestResponseValid(respToken.resp, respToken.json).valid) return undefined

    tokens.accessToken = `Bearer ${respToken.json.accessToken}`
    return tokens
  }

  protected async newRefreshTokens(): Promise<BluelinkTokens | undefined> {
    if (!this.cache?.token.additionalTokens || !isNotEmptyObject(this.cache.token.additionalTokens)) return undefined

    const respTokens = await this.request({
      url: `https://${this.apiConfig.newApiDomain}/domain/api/v2/auth/token-refresh`,
      data: JSON.stringify({
        accessToken: this.cache.token.additionalTokens['access'],
        refreshToken: this.cache.token.additionalTokens['refresh'],
        exchangeableAccessToken: this.cache.token.additionalTokens['exchangeableAccess'],
        exchangeableRefreshToken: this.cache.token.additionalTokens['exchangeableRefresh'],
        nonCcsToken: this.cache.token.additionalTokens['nonCcsToken'],
        nonCcsRefreshToken: this.cache.token.additionalTokens['nonCcsRefreshToken'],
      }),
      noAuth: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: {
        'client-id': 'com.kia.oneapp.eu',
        Authentication: this.cache.token.additionalTokens['idToken'] ?? '',
        Authorization: `Bearer ${this.cache.token.additionalTokens['access'] ?? ''}`,
        'exchangeable-token': this.cache.token.additionalTokens['exchangeableAccess'] ?? '',
        'non-ccs-token': this.cache.token.additionalTokens['nonCcsToken'] ?? '',
      },
    })

    if (this.requestResponseValid(respTokens.resp, respTokens.json).valid) {
      return this.tokenExchange({
        accessToken: '',
        refreshToken: '',
        expiry: Math.floor(Date.now() / 1000) + Number(respTokens.json.expiresIn),
        authId: await this.getDeviceId(),
        additionalTokens: {
          access: respTokens.json.accessToken,
          refresh: respTokens.json.refreshToken,
          exchangeableAccess: respTokens.json.exchangeableAccessToken,
          exchangeableRefresh: respTokens.json.exchangeableRefreshToken,
          nonCcsToken: respTokens.json.nonCcsToken,
          nonCcsRefreshToken: respTokens.json.nonCcsRefreshToken,
          idToken: respTokens.json.idToken,
        },
      })
    }

    return undefined
  }

  // Refresh a Hyundai OneApp (CCI) token set: POST /auth/v2/token-refresh with
  // the full token set, signed with X-Fingerprint, then re-exchange the CCS
  // token. Falls back to the legacy domain/api route.
  protected async hyundaiOneAppRefresh(): Promise<BluelinkTokens | undefined> {
    const at = this.cache?.token?.additionalTokens
    if (!at || !isNotEmptyObject(at)) return undefined
    const cciDomain = this.apiConfig.cciApiDomain
    if (!cciDomain) return undefined

    const deviceId = this.cache.token.authId ?? this.generateUUID()
    const body = JSON.stringify({
      accessToken: at['access'],
      refreshToken: at['refresh'],
      exchangeableAccessToken: at['exchangeableAccess'],
      exchangeableRefreshToken: at['exchangeableRefresh'],
      nonCcsToken: at['nonCcsToken'],
      nonCcsRefreshToken: at['nonCcsRefreshToken'],
      idToken: at['idToken'],
    })

    const fpHeaders = this.buildCciFingerprintHeaders(deviceId)
    fpHeaders['Content-Type'] = 'application/json'

    const respTokens = await this.request({
      url: `https://${cciDomain}/auth/v2/token-refresh`,
      method: 'POST',
      data: body,
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: fpHeaders,
    })

    if (this.requestResponseValid(respTokens.resp, respTokens.json).valid && respTokens.json.accessToken) {
      return await this.cciTokenExchange(
        {
          accessToken: '',
          refreshToken: '',
          expiry: Math.floor(Date.now() / 1000) + Number(respTokens.json.expiresIn ?? 3600),
          authId: deviceId,
          additionalTokens: {
            access: respTokens.json.accessToken,
            refresh: respTokens.json.refreshToken,
            exchangeableAccess: respTokens.json.exchangeableAccessToken,
            exchangeableRefreshToken: respTokens.json.exchangeableRefreshToken,
            nonCcsToken: respTokens.json.nonCcsToken,
            nonCcsRefreshToken: respTokens.json.nonCcsRefreshToken,
            idToken: respTokens.json.idToken,
          },
        },
        deviceId,
      )
    }

    // Fallback: legacy unsigned domain/api refresh
    console.log('[Europe] Fingerprint-gated refresh failed — trying legacy route')
    const legacyHeaders = this.buildCciLegacyHeaders(deviceId, {
      cciAccess: at['access'],
      nonCcsToken: at['nonCcsToken'],
      exchangeable: at['exchangeableAccess'],
    })
    legacyHeaders['Content-Type'] = 'application/json'

    const legacy = await this.request({
      url: `https://${cciDomain}/domain/api/v2/auth/token-refresh`,
      method: 'POST',
      data: body,
      noAuth: true,
      disableAdditionalHeaders: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: legacyHeaders,
    })

    if (this.requestResponseValid(legacy.resp, legacy.json).valid && legacy.json.accessToken) {
      return await this.cciTokenExchange(
        {
          accessToken: '',
          refreshToken: '',
          expiry: Math.floor(Date.now() / 1000) + Number(legacy.json.expiresIn ?? 3600),
          authId: deviceId,
          additionalTokens: {
            access: legacy.json.accessToken,
            refresh: legacy.json.refreshToken,
            exchangeableAccess: legacy.json.exchangeableAccessToken,
            exchangeableRefreshToken: legacy.json.exchangeableRefreshToken,
            nonCcsToken: legacy.json.nonCcsToken,
            nonCcsRefreshToken: legacy.json.nonCcsRefreshToken,
            idToken: legacy.json.idToken,
          },
        },
        deviceId,
      )
    }
    return undefined
  }

  protected async refreshTokens(): Promise<BluelinkTokens | undefined> {
    if (this.cache?.token.additionalTokens) {
      // Hyundai OneApp sessions refresh through the CCI route; Kia through its own
      if (this.config.manufacturer === 'hyundai' && this.apiConfig.cciApiDomain) {
        return await this.hyundaiOneAppRefresh()
      }
      return await this.newRefreshTokens()
    }

    if (!this.cache?.token.refreshToken) return undefined

    // Hyundai uses IDP endpoint for refresh
    if (this.apiConfig.authClientSecret) {
      return await this.hyundaiRefreshTokens()
    }

    const resp = await this.request({
      url: `${this.apiDomain}/api/v1/user/oauth2/token`,
      data: [
        `client_id=${this.apiConfig.clientId}`,
        'grant_type=refresh_token',
        `refresh_token=${this.cache.token.refreshToken}`,
        `redirect_uri=${this.apiDomain}/api/v1/user/oauth2/redirect`,
      ].join('&'),
      noAuth: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: {
        Authorization: this.apiConfig.authBasic,
        Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb),
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    })
    if (this.requestResponseValid(resp.resp, resp.json).valid) {
      return {
        authCookie: '',
        accessToken: `Bearer ${resp.json.access_token}`,
        refreshToken: resp.json.refresh_token || this.cache.token.refreshToken,
        expiry: Math.floor(Date.now() / 1000) + Number(resp.json.expires_in),
        authId: await this.getDeviceId(),
      }
    }
    return undefined
  }

  protected async hyundaiRefreshTokens(): Promise<BluelinkTokens | undefined> {
    if (!this.cache?.token.refreshToken) return undefined
    return await this.refreshHyundaiToken(this.cache.token.refreshToken)
  }

  protected async getDeviceId(): Promise<string | undefined> {
    const resp = await this.request({
      url: `${this.apiDomain}/api/v1/spa/notifications/register`,
      data: JSON.stringify({
        pushRegId: `${this.genRanHex(22)}:${this.genRanHex(63)}-${this.genRanHex(55)}`,
        pushType: this.apiConfig.pushType,
        uuid: this.generateUUID(),
      }),
      noAuth: true,
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: { Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb) },
    })
    if (this.requestResponseValid(resp.resp, resp.json).valid) {
      const deviceId = resp.json.resMsg?.deviceId
      if (deviceId) {
        console.log('[Europe] Obtained deviceId from notifications/register')
      } else {
        console.error('[Europe] notifications/register succeeded but deviceId missing from response')
      }
      return deviceId
    }
    console.error(`[Europe] Failed to register for notifications (deviceId): status=${resp.resp.statusCode}`)
    return undefined
  }

  protected async getCar(): Promise<BluelinkCar | undefined> {
    let vin = this.vin
    if (!vin && this.cache) vin = this.cache.car.vin

    const resp = await this.request({
      url: this.apiDomain + '/api/v1/spa/vehicles',
      validResponseFunction: this.requestResponseValid.bind(this),
      headers: { Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb) },
    })

    if (!this.requestResponseValid(resp.resp, resp.json).valid) {
      throw Error(`Failed to retrieve vehicles: ${JSON.stringify(resp.json)}`)
    }

    if (resp.json.resMsg.vehicles.length > 1 && !vin) {
      for (const vehicle of resp.json.resMsg.vehicles) {
        this.carOptions.push({ vin: vehicle.vin, nickName: vehicle.nickname, modelName: vehicle.vehicleName, modelYear: vehicle.year })
      }
      return undefined
    }

    if (resp.json.resMsg.vehicles.length > 0) {
      let vehicle = resp.json.resMsg.vehicles[0]
      if (vin) {
        for (const v of resp.json.resMsg.vehicles) {
          if (v.vin === vin) { vehicle = v; break }
        }
      }
      this.europeccs2 = vehicle.ccuCCS2ProtocolSupport
      return {
        id: vehicle.vehicleId,
        vin: vehicle.vin,
        nickName: vehicle.nickname,
        modelName: vehicle.vehicleName,
        modelYear: vehicle.year,
        odometer: 0,
        modelColour: vehicle.detailInfo?.outColor,
        modelTrim: vehicle.detailInfo?.saleCarmdlCd,
        europeccs2: vehicle.ccuCCS2ProtocolSupport,
      }
    }
    throw Error(`Failed to retrieve vehicle list: ${JSON.stringify(resp.json)}`)
  }

  protected returnCarStatus(status: any, updateTime: number): BluelinkStatus {
    const newOdometer = this.convertDistance(status.Drivetrain.Odometer)

    let isCharging = false
    let chargingPower = 0
    const isPluggedIn = status.Green.ChargingInformation.ConnectorFastening.State > 0
    const realTimePower = status.Green.Electric?.SmartGrid?.RealTimePower ?? 0
    const remainTime = status.Green.ChargingInformation.Charging.RemainTime
    // Charging is active when plugged in AND either power is flowing OR an ETA has been computed.
    // Slow AC charging often reports RemainTime: 0 even while charging is in progress.
    if (isPluggedIn && (realTimePower > 0 || remainTime > 0)) {
      isCharging = true
      chargingPower = realTimePower
    }

    const chargeLimit: ChargeLimit = { dcPercent: 0, acPercent: 0 }
    if (status.Green.ChargingInformation?.TargetSoC) {
      chargeLimit.acPercent = status.Green.ChargingInformation.TargetSoC.Standard
      chargeLimit.dcPercent = status.Green.ChargingInformation.TargetSoC.Quick
    }

    let location: Location | undefined = undefined
    if (status.Location?.GeoCoord) {
      location = { latitude: status.Location.GeoCoord.Latitude, longitude: status.Location.GeoCoord.Longitude }
    }

    return {
      lastStatusCheck: Date.now(),
      lastRemoteStatusCheck: Number(updateTime),
      isCharging,
      isPluggedIn: status.Green.ChargingInformation.ConnectorFastening.State > 0,
      chargingPower,
      remainingChargeTimeMins: status.Green.ChargingInformation.Charging.RemainTime,
      range:
        status.Drivetrain.FuelSystem.DTE.Total > 0
          ? this.convertDistance(status.Drivetrain.FuelSystem.DTE.Total)
          : this.cache?.status.range ?? 0,
      locked: !(
        Boolean(status.Cabin.Door.Row1.Driver.Open) &&
        Boolean(status.Cabin.Door.Row1.Passenger.Open) &&
        Boolean(status.Cabin.Door.Row2.Driver.Open) &&
        Boolean(status.Cabin.Door.Row2.Passenger.Open)
      ),
      climate: Boolean(status.Cabin.HVAC.Row1.Driver.Blower.SpeedLevel > 0),
      soc: status.Green.BatteryManagement.BatteryRemain.Ratio,
      twelveSoc: status.Electronics?.Battery?.Level ?? 0,
      odometer: newOdometer || (this.cache?.status.odometer ?? 0),
      location: location ?? this.cache?.status.location,
      chargeLimit: chargeLimit.acPercent > 0 ? chargeLimit : this.cache?.status.chargeLimit,
    }
  }

  protected async getCarStatus(id: string, forceUpdate: boolean, _location = false): Promise<BluelinkStatus> {
    if (!forceUpdate) {
      const resp = await this.request({
        url: `${this.apiDomain}/api/v1/spa/vehicles/${id}/ccs2/carstatus/latest`,
        headers: { Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb), ccuCCS2ProtocolSupport: this.getCCS2Header() },
        validResponseFunction: this.requestResponseValid.bind(this),
      })
      if (this.requestResponseValid(resp.resp, resp.json).valid) {
        return this.returnCarStatus(resp.json.resMsg.state.Vehicle, resp.json.resMsg.lastUpdateTime)
      }
      throw Error(`Failed to retrieve vehicle status: ${JSON.stringify(resp.json)}`)
    }

    const currentTime = Date.now()
    await this.request({
      url: `${this.apiDomain}/api/v1/spa/vehicles/${id}/ccs2/carstatus`,
      headers: { Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb), ccuCCS2ProtocolSupport: this.getCCS2Header() },
      validResponseFunction: this.requestResponseValid.bind(this),
    })

    let attempts = 0
    while (attempts <= MAX_COMPLETION_POLLS) {
      attempts++
      await this.sleep(2000)
      const status = await this.getCarStatus(id, false)
      if (currentTime < status.lastRemoteStatusCheck) return status
    }

    throw Error('Failed to retrieve remote vehicle status: timed out polling')
  }

  protected async getAuthCode(id: string): Promise<string> {
    if (this.controlToken && this.controlToken.expiry > Date.now()) {
      return this.controlToken.token
    }

    // Ensure deviceId exists — if missing from cache, attempt to obtain one
    let deviceId = this.cache?.token?.authId
    if (!deviceId) {
      console.error('[Europe] getAuthCode: deviceId missing from cache, attempting to obtain one')
      deviceId = await this.getDeviceId()
      if (deviceId && this.cache?.token) {
        this.cache.token.authId = deviceId
        await this.saveCache()
      }
    }

    console.log('[Europe] getAuthCode: deviceId=' + (deviceId ? 'present' : 'MISSING') + ', pin=' + (this.config.auth.pin ? 'present' : 'MISSING'))

    if (!deviceId || !this.config.auth.pin) {
      throw Error(`Cannot send command: ${!deviceId ? 'deviceId is missing' : 'PIN is missing'}. Please reconnect your vehicle.`)
    }

    const resp = await this.request({
      url: `${this.apiDomain}/api/v1/user/pin`,
      method: 'PUT',
      data: JSON.stringify({ pin: this.config.auth.pin, deviceId }),
      headers: { vehicleId: id, Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb), ccuCCS2ProtocolSupport: this.getCCS2Header() },
      validResponseFunction: this.requestResponseValid.bind(this),
    })
    if (this.requestResponseValid(resp.resp, resp.json).valid) {
      this.controlToken = {
        expiry: Date.now() + Number(resp.json.expiresTime) * 1000,
        token: `Bearer ${resp.json.controlToken}`,
      }
      return this.controlToken.token
    }
    throw Error(`Failed to get auth code: ${JSON.stringify(resp.json)}`)
  }

  protected async pollForCommandCompletion(id: string, transactionId: string, maxPolls: number = MAX_COMPLETION_POLLS): Promise<{ isSuccess: boolean; data: any }> {
    let attempts = 0
    while (attempts <= maxPolls) {
      const resp = await this.request({
        url: `${this.apiDomain}/api/v1/spa/notifications/${id}/records`,
        headers: { Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb), ccuCCS2ProtocolSupport: this.getCCS2Header() },
        validResponseFunction: this.requestResponseValid.bind(this),
      })

      if (!this.requestResponseValid(resp.resp, resp.json).valid) {
        throw Error(`Poll failed: ${JSON.stringify(resp.json)}`)
      }

      for (const record of resp.json.resMsg) {
        if (record.recordId === transactionId) {
          const result = record.result
          if (result) {
            switch (result) {
              case 'success':
                return { isSuccess: true, data: (await this.getStatus(false, true)).status }
              case 'fail':
              case 'non-response':
                return { isSuccess: false, data: record }
            }
          }
        }
      }

      attempts++
      await this.sleep(2000)
    }
    return { isSuccess: false, data: undefined }
  }

  protected async lock(id: string) { return await this.lockUnlock(id, true) }
  protected async unlock(id: string) { return await this.lockUnlock(id, false) }

  protected async lockUnlock(id: string, shouldLock: boolean): Promise<{ isSuccess: boolean; data: BluelinkStatus }> {
    const resp = await this.request({
      url: `${this.apiDomain}/api/v2/spa/vehicles/${id}/ccs2/control/door`,
      method: 'POST',
      data: JSON.stringify({ command: shouldLock ? 'close' : 'open', ccuCCS2ProtocolSupport: this.getCCS2Header() }),
      headers: { Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb), ccuCCS2ProtocolSupport: this.getCCS2Header() },
      authTokenOverride: await this.getAuthCode(id),
      validResponseFunction: this.requestResponseValid.bind(this),
    })
    if (this.requestResponseValid(resp.resp, resp.json).valid) {
      this.setLastCommandSent()
      const transactionId = resp.json.msgId
      if (transactionId) return await this.pollForCommandCompletion(id, transactionId)
    }
    throw Error(`Failed to send lockUnlock: ${JSON.stringify(resp.json)}`)
  }

  protected async startCharge(id: string) { return await this.chargeStopCharge(id, true) }
  protected async stopCharge(id: string) { return await this.chargeStopCharge(id, false) }

  protected async chargeStopCharge(id: string, shouldCharge: boolean): Promise<{ isSuccess: boolean; data: BluelinkStatus }> {
    const resp = await this.request({
      url: `${this.apiDomain}/api/v2/spa/vehicles/${id}/ccs2/control/charge`,
      method: 'POST',
      data: JSON.stringify({ command: shouldCharge ? 'start' : 'stop', ccuCCS2ProtocolSupport: this.getCCS2Header() }),
      headers: { Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb), ccuCCS2ProtocolSupport: this.getCCS2Header() },
      authTokenOverride: await this.getAuthCode(id),
      validResponseFunction: this.requestResponseValid.bind(this),
    })
    if (this.requestResponseValid(resp.resp, resp.json).valid) {
      this.setLastCommandSent()
      const transactionId = resp.json.msgId
      if (transactionId) return await this.pollForCommandCompletion(id, transactionId, CHARGE_COMPLETION_POLLS)
    }
    throw Error(`Failed to send charge command: ${JSON.stringify(resp.json)}`)
  }

  protected async climateOn(id: string, config: ClimateRequest): Promise<{ isSuccess: boolean; data: BluelinkStatus }> {
    const heatingFields = this.isCCS2()
      ? { strgWhlHeating: config.steering ? 1 : 0, sideRearMirrorHeating: config.rearDefrost ? 1 : 0 }
      : { heating1: this.getHeatingValue(config.rearDefrost, config.steering) }

    return await this.climateStartStop(id, {
      command: 'start',
      windshieldFrontDefogState: config.frontDefrost,
      hvacTempType: 1,
      ...heatingFields,
      tempUnit: this.config.tempType,
      drvSeatLoc: this.distanceUnit === 'mi' ? 'R' : 'L',
      hvacTemp: config.temp,
      ...(config.seatClimateOption &&
        isNotEmptyObject(config.seatClimateOption) && {
          seatClimateInfo: {
            drvSeatClimateState: config.seatClimateOption!.driver,
            psgSeatClimateState: config.seatClimateOption!.passenger,
            rlSeatClimateState: config.seatClimateOption!.rearLeft,
            rrSeatClimateState: config.seatClimateOption!.rearRight,
          },
        }),
    })
  }

  protected async climateOff(id: string): Promise<{ isSuccess: boolean; data: BluelinkStatus }> {
    return await this.climateStartStop(id, { command: 'stop' })
  }

  protected async climateStartStop(id: string, climateRequest: any, retryWithNoSeat = false): Promise<{ isSuccess: boolean; data: BluelinkStatus }> {
    const resp = await this.request({
      url: `${this.apiDomain}/api/v2/spa/vehicles/${id}/ccs2/control/temperature`,
      method: 'POST',
      data: JSON.stringify(climateRequest),
      headers: { Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb), ccuCCS2ProtocolSupport: this.getCCS2Header() },
      authTokenOverride: await this.getAuthCode(id),
      validResponseFunction: this.requestResponseValid.bind(this),
    })
    if (this.requestResponseValid(resp.resp, resp.json).valid) {
      this.setLastCommandSent()
      const transactionId = resp.json.msgId
      if (transactionId) return await this.pollForCommandCompletion(id, transactionId)
    } else {
      if (!retryWithNoSeat && climateRequest.seatClimateInfo) {
        delete climateRequest.seatClimateInfo
        return this.climateStartStop(id, climateRequest, true)
      }
    }
    throw Error(`Failed to send climate command: ${JSON.stringify(resp.json)}`)
  }

  protected async setChargeLimit(id: string, config: ChargeLimit): Promise<{ isSuccess: boolean; data: BluelinkStatus }> {
    const resp = await this.request({
      url: `${this.apiDomain}/api/v1/spa/vehicles/${id}/charge/target`,
      method: 'POST',
      data: JSON.stringify({
        targetSOClist: [
          { plugType: 0, targetSOClevel: config.dcPercent },
          { plugType: 1, targetSOClevel: config.acPercent },
        ],
      }),
      headers: { Stamp: this.getStamp(this.apiConfig.appId, this.apiConfig.authCfb), ccuCCS2ProtocolSupport: this.getCCS2Header() },
      validResponseFunction: this.requestResponseValid.bind(this),
    })
    if (this.requestResponseValid(resp.resp, resp.json).valid) {
      this.setLastCommandSent()
      return { isSuccess: true, data: await this.getCarStatus(id, true) }
    }
    throw Error(`Failed to send chargeLimit: ${JSON.stringify(resp.json)}`)
  }
}
