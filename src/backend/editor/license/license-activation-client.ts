/**
 * Device license-activation client (PLA-06).
 *
 * HYBRID design (design.md §4): the **real** autonomy-edge client is wired
 * up now, behind a dev **toggle** that injects a mocked response so both
 * code paths are testable today — the real `vpp-licenses/activate` route
 * does not exist on the edge yet (only billing/Paddle/subscriptions do).
 *
 * TODO(D49/D51): remover o toggle quando o modulo vpp-licenses do
 * autonomy-edge existir.
 *
 * Runs main-side: uses `node:https` + the same base-URL / `{ statusCode,
 * data }` envelope conventions as the library catalog client.
 */

import { createHash, createHmac } from 'node:crypto'
import https from 'https'

import { getEdgeApiBaseUrl } from '../library-manager/desktop-catalog-transport'

/** Request payload sent to the edge activation endpoint. */
export interface DeviceActivationInput {
  /** 16-byte device id, hex (from `deriveDeviceId`). */
  deviceId: string
  /** 8-byte VPP id, hex (from `deriveVppId`). */
  vppId: string
  /** VPP package id (e.g. `com.openplc.espressif`). */
  packageId: string
}

/** Result of an activation check. Best-effort: transport / backend errors
 *  surface as `{ licensed: false, error }` rather than throwing, so the
 *  post-flash routine can degrade to demo mode without a hard failure. */
export interface DeviceActivationResult {
  licensed: boolean
  /** License blob bytes (46 B, HMAC) when `licensed` — ready to write via FC 0x49. */
  license?: number[]
  /** Backend-supplied reason (e.g. "no active subscription"). */
  reason?: string
  /** Populated on transport / backend failure (best-effort path). */
  error?: string
}

const ACTIVATE_PATH = '/vpp-licenses/activate'
const REQUEST_TIMEOUT_MS = 30_000

/**
 * Check whether a device is entitled to a license for the given VPP.
 *
 * `process.env.OPLC_LICENSE_MOCK` short-circuits the network:
 *   - `'licensed'` → `{ licensed: true, license: <46-byte HMAC blob for this device> }`
 *     (exercises the on-device write + verify path; built with the TEST key).
 *   - `'demo'`     → `{ licensed: false }`.
 *   - absent       → calls the real edge client (§4).
 */
export async function checkDeviceActivation(input: DeviceActivationInput): Promise<DeviceActivationResult> {
  // TODO(D49/D51): remover o toggle quando o modulo vpp-licenses do autonomy-edge existir.
  const mock = process.env.OPLC_LICENSE_MOCK
  if (mock === 'licensed') {
    return { licensed: true, license: hmacLicenseBytes(input) }
  }
  if (mock === 'demo') {
    return { licensed: false }
  }

  return activateViaEdge(input)
}

// ---------------------------------------------------------------------------
// Real edge client (best-effort)
// ---------------------------------------------------------------------------

/**
 * POST `{base}/vpp-licenses/activate`, unwrapping the edge `{ statusCode,
 * data }` envelope. Any failure (route missing → 404, network, non-2xx,
 * bad JSON) resolves to `{ licensed: false, error }` — never throws.
 */
async function activateViaEdge(input: DeviceActivationInput): Promise<DeviceActivationResult> {
  try {
    const raw = await postJson(`${getEdgeApiBaseUrl()}${ACTIVATE_PATH}`, input)
    const data = unwrapHttpEnvelope(raw) as Partial<DeviceActivationResult> | undefined
    if (!data || typeof data.licensed !== 'boolean') {
      return { licensed: false, error: 'Unexpected activation response shape' }
    }
    return { licensed: data.licensed, license: data.license, reason: data.reason }
  } catch (err) {
    return { licensed: false, error: err instanceof Error ? err.message : String(err) }
  }
}

function postJson(url: string, body: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url)
    const payload = JSON.stringify(body)
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Content-Length': String(Buffer.byteLength(payload)),
      Accept: 'application/json',
      'User-Agent': 'OpenPLC-Editor/license-activation',
    }
    // Send the account JWT when one is available; the route will require it
    // once it exists. Without a token the request still goes out (and 401/404
    // → best-effort demo). No edge-account token authority exists yet, so this
    // reads an env override for now.
    const token = process.env.OPENPLC_EDGE_TOKEN?.trim()
    if (token) headers.Authorization = `Bearer ${token}`

    const req = https.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || undefined,
        path: parsed.pathname + parsed.search,
        method: 'POST',
        headers,
      },
      (res) => {
        let responseBody = ''
        res.setEncoding('utf-8')
        res.on('data', (chunk: string) => {
          responseBody += chunk
        })
        res.on('end', () => {
          const status = res.statusCode ?? 0
          if (status < 200 || status >= 300) {
            reject(new Error(`Activation request failed: ${status} ${res.statusMessage ?? ''}`.trim()))
            return
          }
          try {
            resolve(JSON.parse(responseBody))
          } catch (err) {
            reject(new Error(`Activation response was not valid JSON: ${err instanceof Error ? err.message : err}`))
          }
        })
      },
    )

    req.setTimeout(REQUEST_TIMEOUT_MS, () => {
      req.destroy(new Error(`Activation request timed out after ${REQUEST_TIMEOUT_MS}ms`))
    })
    req.on('error', (err) => reject(err))
    req.write(payload)
    req.end()
  })
}

/** autonomy-edge wraps JSON responses in `{ statusCode, data }`. Unwrap once
 *  so callers see the payload; off-spec responses fall through unchanged. */
function unwrapHttpEnvelope(raw: unknown): unknown {
  if (raw && typeof raw === 'object' && 'data' in raw && 'statusCode' in raw) {
    return (raw as { data: unknown }).data
  }
  return raw
}

// ---------------------------------------------------------------------------
// Mock HMAC blob (spike)
// ---------------------------------------------------------------------------

/** 'OPLC' magic bytes. */
const LIC_MAGIC = [0x4f, 0x50, 0x4c, 0x43]
/** fmt_version 2 = HMAC layout. */
const FMT_VERSION_HMAC = 2
/**
 * Deterministic 32-byte TEST key, identical to the one baked into the esp8266
 * .a (gen-license-golden.ts / wsl-rebuild-a-hmac.sh derive it the same way).
 * NOT a production secret — real per-VPP keys come from the backend.
 */
const HMAC_TEST_KEY = createHash('sha256').update(Buffer.from('openplc-license-hmac-test-key-v1', 'ascii')).digest()

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(Math.floor(hex.length / 2))
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/**
 * SPIKE mock: build a valid 46-byte HMAC license blob for THIS device, keyed by
 * the TEST key baked into the .a. It uses the caller's real deviceId/vppId, so
 * the device's on-boot verify (recompute device_id + HMAC tag) passes -> FULL.
 * Grants a license to whatever device asks; stands in for the backend issue.
 *
 *   payload(30) = magic | fmt=2 | keyId=0 | deviceId[16] | productId[8]
 *   tag(16)     = HMAC-SHA256(TEST_KEY, payload)[:16]
 *   blob(46)    = payload || tag
 */
function hmacLicenseBytes(input: DeviceActivationInput): number[] {
  const deviceId = hexToBytes(input.deviceId)
  const productId = hexToBytes(input.vppId)

  const payload = new Uint8Array(30)
  payload.set(LIC_MAGIC, 0)
  payload[4] = FMT_VERSION_HMAC
  payload[5] = 0 // keyId
  payload.set(deviceId.subarray(0, 16), 6)
  payload.set(productId.subarray(0, 8), 22)

  const tag = createHmac('sha256', HMAC_TEST_KEY).update(Buffer.from(payload)).digest().subarray(0, 16)

  const blob = new Uint8Array(46)
  blob.set(payload, 0)
  blob.set(tag, 30)
  return Array.from(blob)
}
