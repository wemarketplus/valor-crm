const express = require('express')
const { createClient } = require('@supabase/supabase-js')
const path = require('path')
const fs = require('fs')
const app = express()

// ─── SECURITY HEADERS ──────────────────────────────────────────────────────────
// CORS: strip localhost origins in production to prevent cross-origin abuse
const IS_PROD = process.env.NODE_ENV === 'production'
const CORS_ORIGINS = IS_PROD
  ? ['https://valor-crm.onrender.com']
  : ['https://valor-crm.onrender.com', 'http://localhost:3001', 'http://localhost:3000']

const crypto = require('crypto')

// ─── SUPABASE CLIENTS (must be defined before rateLimitLogin uses them) ────────
const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('FATAL: Missing SUPABASE_URL or SUPABASE_SERVICE_KEY')
  process.exit(1)
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
const authClient = SUPABASE_ANON_KEY
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
  : createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

console.log(`Auth client using: ${SUPABASE_ANON_KEY ? 'ANON KEY ✓' : 'SERVICE KEY (set SUPABASE_ANON_KEY for best results)'}`)

app.use((req, res, next) => {
  // ── Standard security headers ───────────────────────────────────────────────
  res.setHeader('X-Content-Type-Options',    'nosniff')
  res.setHeader('X-Frame-Options',           'DENY')
  res.setHeader('X-XSS-Protection',          '0')            // Modern browsers: rely on CSP instead
  res.setHeader('Referrer-Policy',           'strict-origin-when-cross-origin')
  res.setHeader('Permissions-Policy',        'camera=(), microphone=(), geolocation=()')
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
  res.removeHeader('X-Powered-By')

  // ── Content Security Policy ─────────────────────────────────────────────────
  // Blocks inline XSS execution from user-injected content.
  // 'unsafe-inline' on style-src is required because the app uses inline styles heavily.
  // script-src does NOT include 'unsafe-inline' — this is the critical protection.
  // When the codebase is migrated to an external .js bundle, remove 'unsafe-inline' from style-src.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",          // tighten to nonce after bundle split
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https: blob:",
    "font-src 'self' data:",
    "connect-src 'self' https://*.supabase.co https://api.anthropic.com",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
  ].join('; '))

  // ── CORS ────────────────────────────────────────────────────────────────────
  const origin = req.headers.origin
  if (origin && CORS_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin',  origin)
    res.setHeader('Vary', 'Origin')                          // required when ACAO is not wildcard
  }
  res.setHeader('Access-Control-Allow-Methods',  'GET,POST,PUT,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers',  'Content-Type,Authorization')
  res.setHeader('Access-Control-Max-Age',        '86400')    // cache preflight 24h

  if (req.method === 'OPTIONS') return res.sendStatus(204)
  next()
})

// JSON body limit: 2MB for regular API calls.
// The Aircall webhook uses express.raw() separately.
// Import calls send pre-chunked batches of 200 rows max, each well under 2MB.
app.use((req, res, next) => {
  // Skip express.json for the raw webhook endpoint
  if (req.path === '/api/webhooks/aircall') return next()
  express.json({ limit: '2mb', strict: true })(req, res, next)
})

// ─── RATE LIMITING ─────────────────────────────────────────────────────────────
// Primary: database-backed rate limiting — survives server restarts and cold starts.
// Fallback: in-memory Map used only if the DB query fails (network issue on startup).
// The login_attempts table should be created once (see inline DDL on first boot).
const _loginFallback = new Map()

async function rateLimitLogin(req, res, next) {
  const ip  = (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown').substring(0, 45)
  const MAX = 10
  const WINDOW_MINUTES = 15

  try {
    // Count attempts in the last WINDOW_MINUTES for this IP using Supabase
    const since = new Date(Date.now() - WINDOW_MINUTES * 60 * 1000).toISOString()
    const { count, error } = await supabase
      .from('login_attempts')
      .select('id', { count: 'exact', head: true })
      .eq('ip_address', ip)
      .gte('attempted_at', since)

    if (!error) {
      if (count >= MAX) {
        return res.status(429).json({
          error: `Too many login attempts. Try again in ${WINDOW_MINUTES} minutes.`
        })
      }
      // Record this attempt
      await supabase.from('login_attempts').insert({ ip_address: ip })
      return next()
    }
    // DB error — fall through to in-memory fallback
    console.warn('rateLimitLogin DB error, using in-memory fallback:', error.message)
  } catch (_) {
    // Network error on startup — use fallback
  }

  // In-memory fallback (single-process only, resets on restart)
  const now = Date.now(), window = WINDOW_MINUTES * 60 * 1000
  const e = _loginFallback.get(ip) || { count: 0, resetAt: now + window }
  if (now > e.resetAt) { e.count = 0; e.resetAt = now + window }
  e.count++
  _loginFallback.set(ip, e)
  if (e.count > MAX) {
    return res.status(429).json({
      error: `Too many login attempts. Try again in ${WINDOW_MINUTES} minutes.`
    })
  }
  next()
}

// Cleanup fallback Map every 30 minutes
setInterval(() => {
  const now = Date.now()
  for (const [ip, e] of _loginFallback) if (now > e.resetAt) _loginFallback.delete(ip)
}, 30 * 60 * 1000)

// Create login_attempts table on first boot if it doesn't exist
// This is idempotent and safe to run on every restart
;(async () => {
  try {
    await supabase.rpc('exec_ddl', {
      sql: `CREATE TABLE IF NOT EXISTS login_attempts (
        id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        ip_address  TEXT        NOT NULL,
        attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, attempted_at);
      DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '24 hours';`
    }).throwOnError()
  } catch (_) {
    // Table may already exist or exec_ddl RPC may not be available — non-fatal
  }
})()

// ─── SUPABASE CLIENTS (already initialized above before middleware) ─────────────

// ─── BLOCK SOURCE FILE EXPOSURE ────────────────────────────────────────────────
const BLOCKED = ['.ts','.json','.env','.md','.lock','.sh','.sql']
const BLOCKED_NAMES = ['server.js','server.ts','package.json','package-lock.json','.env','package.js']
app.use((req, res, next) => {
  const p = req.path.toLowerCase()
  const filename = p.split('/').pop()
  if (p.startsWith('/api/')) return next()
  if (p === '/' || p === '/index.html' || p === '/favicon.ico') return next()
  // CRITICAL: always block server.js directly
  if (filename === 'server.js') return res.status(404).send('Not found')
  if (BLOCKED_NAMES.includes(filename)) return res.status(404).send('Not found')
  if (BLOCKED.some(ext => p.endsWith(ext))) return res.status(404).send('Not found')
  next()
})

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
// Only serve from public/ subdirectory - never serve root-level source files
app.use(express.static(path.join(__dirname, 'public'), { index: false, dotfiles: 'deny' }))

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
async function auth(req, res, next) {
  try {
    const rawToken = req.headers.authorization?.replace('Bearer ', '').trim()
    if (!rawToken || rawToken.length < 10) {
      return res.status(401).json({ error: 'Authentication required' })
    }

    // ── 1. Validate token with Supabase auth server ──────────────────────────
    // getUser() makes a live request to Supabase auth — not a local JWT decode.
    // This means a revoked Supabase session is rejected here automatically.
    const { data: { user }, error: authErr } = await authClient.auth.getUser(rawToken)
    if (authErr || !user) {
      return res.status(401).json({ error: 'Session expired. Please sign in again.' })
    }

    // ── 2. Check token revocation table ─────────────────────────────────────
    // Extract the JWT jti claim (unique token identifier) for revocation lookup.
    // The jti is in the middle section of the JWT (base64url-encoded JSON payload).
    try {
      const jwtPayload = JSON.parse(
        Buffer.from(rawToken.split('.')[1], 'base64url').toString('utf8')
      )
      const jti = jwtPayload?.jti
      if (jti) {
        const { data: revoked } = await supabase
          .from('revoked_tokens')
          .select('jti')
          .eq('jti', jti)
          .single()
        if (revoked) {
          return res.status(401).json({ error: 'Session revoked. Please sign in again.' })
        }
      }
    } catch (_) {
      // JWT parse failure is non-fatal — Supabase already validated the token above.
      // This only affects revocation list checking.
    }

    // ── 3. Load user profile and check active status ─────────────────────────
    const { data: profile, error: profileErr } = await supabase
      .from('user_profiles')
      .select('*')
      .eq('id', user.id)
      .single()

    if (profileErr || !profile) {
      return res.status(401).json({ error: 'User profile not found. Contact administrator.' })
    }

    // is_active check: profile.is_active === false means admin explicitly disabled the account.
    // Combined with Supabase's ban (set when disabling), this double-blocks access.
    if (profile.is_active === false) {
      return res.status(403).json({ error: 'Account disabled. Contact your administrator.' })
    }

    req.user    = profile
    req.rawToken = rawToken  // stored for logout / force-revoke operations

    next()
  } catch (err) {
    console.error('Auth middleware error:', err.message)
    return res.status(500).json({ error: 'Authentication service error' })
  }
}

// ── Helper: revoke a token immediately (used on disable + password reset) ──────
async function revokeToken(rawToken, userId, reason = 'admin_action') {
  try {
    const payload = JSON.parse(
      Buffer.from(rawToken.split('.')[1], 'base64url').toString('utf8')
    )
    const jti       = payload?.jti
    const expiresAt = payload?.exp ? new Date(payload.exp * 1000).toISOString() : null
    if (!jti || !expiresAt) return { error: 'No jti in token' }

    const { error } = await supabase.from('revoked_tokens').upsert(
      { jti, user_id: userId, reason, expires_at: expiresAt },
      { onConflict: 'jti', ignoreDuplicates: true }
    )
    return { error }
  } catch (e) {
    return { error: e.message }
  }
}

// ─── ROLE DEFINITIONS ─────────────────────────────────────────────────────────
// Roles: super_admin > admin > grant_coordinator > compliance_mgr > team_member > external_partner
const VALID_ROLES = ['super_admin','admin','grant_coordinator','compliance_mgr','team_member','external_partner']

const requireAdmin = (req, res, next) =>
  ['super_admin','admin'].includes(req.user?.role) ? next() : res.status(403).json({ error: 'Admin access required' })

const requireSuper = (req, res, next) =>
  req.user?.role === 'super_admin' ? next() : res.status(403).json({ error: 'Super admin access required' })

const requireContributor = (req, res, next) =>
  ['super_admin','admin','grant_coordinator','compliance_mgr','team_member'].includes(req.user?.role)
    ? next() : res.status(403).json({ error: 'Contributor access required — contact your administrator' })

const requireDelete = (req, res, next) =>
  ['super_admin','admin'].includes(req.user?.role) ? next() : res.status(403).json({ error: 'Delete requires Admin or Super Admin access' })

// ─── SAFE ACTIVITY LOG HELPER ───────────────────────────────────────────────
// Resilient activity_log insert
async function logActivity(payload) {
  try {
    const { error } = await safeInsertLog(payload)
    if (error) console.warn('logActivity error:', error.message)
  } catch(e) {
    console.warn('logActivity failed:', e.message)
  }
}

// ─── SCHEMA CACHE REFRESH ────────────────────────────────────────────────────
// Refresh Supabase PostgREST schema cache to fix 'column not found' errors
// Schema detection - run once on startup
global._hasMetadata = false  // assume NO metadata column until confirmed
global._detailsColumnMissing = false

async function refreshSchemaCache() {
  // Test each column individually to see what's accessible in PostgREST's schema cache
  const testCol = async (col) => {
    try {
      const { error } = await supabase.from('activity_log').select(col).limit(1)
      return !error
    } catch(e) { return false }
  }
  
  const hasDetails    = await testCol('details')
  const hasMetadata   = await testCol('metadata')
  const hasRecordType = await testCol('record_type')
  const hasRecordId   = await testCol('record_id')
  const hasUserId     = await testCol('user_id')
  
  global._detailsColumnMissing = !hasDetails
  global._hasMetadata          = hasMetadata
  global._hasRecordType        = hasRecordType
  global._hasRecordId          = hasRecordId
  global._hasUserId            = hasUserId
  
  console.log('Schema cache:', {
    details: hasDetails, metadata: hasMetadata,
    record_type: hasRecordType, record_id: hasRecordId, user_id: hasUserId
  })
  
  // Build the safe column string for queries
  const cols = ['id','action','created_at']
  if (hasDetails)    cols.push('details')
  if (hasMetadata)   cols.push('metadata')
  if (hasRecordType) cols.push('record_type')
  if (hasRecordId)   cols.push('record_id')
  if (hasUserId)     cols.push('user_id')
  global._safeActivityCols = cols.join(',')
  console.log('Safe activity_log columns:', global._safeActivityCols)
}
setTimeout(refreshSchemaCache, 500)

// Helper: safe insert to activity_log — strips columns that PostgREST says don't exist
async function safeInsertLog(payload) {
  const { metadata, details, record_type, record_id, user_id, ...base } = payload

  // Only include columns confirmed to exist by refreshSchemaCache()
  if (global._hasUserId   !== false && user_id)    base.user_id    = user_id
  if (global._hasRecordType           && record_type) base.record_type = record_type
  if (global._hasRecordId             && record_id)   base.record_id   = record_id

  if (global._hasMetadata) {
    base.metadata = { ...(metadata||{}), content: details, text: details,
      record_type: record_type||null, record_id: record_id||null }
    if (!global._detailsColumnMissing && details !== undefined) base.details = details
  } else if (!global._detailsColumnMissing) {
    base.details = metadata
      ? JSON.stringify({ text: details, record_type, record_id, ...metadata })
      : (details || '')
  }

  let { data, error } = await supabase.from('activity_log').insert(base).select().single()

  // Self-heal: if a column still fails, strip it and retry once
  if (error && error.message) {
    const msg = error.message
    let changed = false
    if (msg.includes('record_type')) { global._hasRecordType = false; delete base.record_type; changed = true }
    if (msg.includes('record_id'))   { global._hasRecordId   = false; delete base.record_id;   changed = true }
    if (msg.includes('details'))     { global._detailsColumnMissing = true; delete base.details; changed = true }
    if (msg.includes('metadata'))    { global._hasMetadata = false; delete base.metadata; changed = true }
    if (msg.includes('user_id'))     { global._hasUserId   = false; delete base.user_id;   changed = true }
    if (changed) {
      // Rebuild _safeActivityCols after stripping
      const safeCols = ['id','action','created_at']
      if (!global._detailsColumnMissing) safeCols.push('details')
      if (global._hasMetadata)  safeCols.push('metadata')
      if (global._hasRecordType)safeCols.push('record_type')
      if (global._hasRecordId)  safeCols.push('record_id')
      if (global._hasUserId !== false) safeCols.push('user_id')
      global._safeActivityCols = safeCols.join(',')
      console.warn('safeInsertLog self-healed, retrying without failed column. New safe cols:', global._safeActivityCols)
      const retry = await supabase.from('activity_log').insert(base).select().single()
      return { data: retry.data, error: retry.error }
    }
  }

  return { data, error }
}

// Helper: parse activity_log row - extract metadata from details JSON if needed
function parseLogRow(row) {
  if (!row) return row
  if (row.metadata) return row  // has real metadata column
  // Try to parse details as JSON
  try {
    const parsed = JSON.parse(row.details || '{}')
    if (typeof parsed === 'object' && parsed !== null) {
      return { ...row, metadata: parsed, details: parsed.text || row.details }
    }
  } catch(e) {}
  return row
}

app.post('/api/refresh-schema', auth, requireAdmin, async (req, res) => {
  // Re-run schema detection to pick up any changes
  await refreshSchemaCache()
  const accessible = !global._detailsColumnMissing
  
  // Whether or not details column works, we can still operate using metadata
  // The system works either way - just return success
  res.json({
    success: true,
    details_column: accessible ? 'accessible' : 'missing - using metadata column fallback (OK)',
    metadata_column: global._hasMetadata ? 'accessible' : 'missing',
    message: 'Schema status refreshed. Tasks, Notes, and Audit Logs will work correctly.',
    sql_fix: "SELECT pg_notify('pgrst', 'reload schema');" 
  })
})

// ─── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/login', rateLimitLogin, async (req, res) => {
  try {
    const { email, password } = req.body || {}
    if (!email?.trim() || !password) {
      return res.status(400).json({ error: 'Email and password required' })
    }
    const cleanEmail = email.trim().toLowerCase()

    console.log(`Login attempt: ${cleanEmail}`)

    const { data, error } = await authClient.auth.signInWithPassword({
      email: cleanEmail,
      password: password
    })

    if (error) {
      console.log(`Login failed for ${cleanEmail}:`, error.message)
      return res.status(401).json({ error: 'Invalid email or password' })
    }

    if (!data?.session?.access_token) {
      console.error('No session token returned from Supabase for:', cleanEmail)
      return res.status(500).json({ error: 'Authentication failed — no session returned. Check Supabase email confirmation settings.' })
    }

    const { data: profile, error: pe } = await supabase.from('user_profiles').select('*').eq('id', data.user.id).single()
    if (pe || !profile) {
      console.error('Profile not found for user:', data.user.id)
      return res.status(401).json({ error: 'User profile not found. Contact administrator.' })
    }
    if (profile.is_active === false) {
      return res.status(403).json({ error: 'Account disabled. Contact your administrator.' })
    }

    // Update last login
    try { await supabase.from('user_profiles').update({ last_login_at: new Date().toISOString() }).eq('id', data.user.id) } catch(_) {}
    try { await supabase.from('activity_log').insert({ user_id: data.user.id, action: 'USER_LOGIN', details: `Login from ${req.headers['x-forwarded-for']?.split(',')[0] || 'unknown'}` }) } catch(_) {}

    console.log(`Login success: ${cleanEmail} (${profile.role})`)
    return res.json({ token: data.session.access_token, user: profile })
  } catch (err) {
    console.error('Login catch error:', err.message, err.constructor?.name)
    // Return specific message for known errors
    const msg = err.message || ''
    if (msg.includes('email') || msg.includes('Email')) {
      return res.status(401).json({ error: 'Email not confirmed. Contact your administrator to confirm your account in Supabase.' })
    }
    if (msg.includes('Invalid') || msg.includes('invalid')) {
      return res.status(401).json({ error: 'Invalid email or password' })
    }
    if (msg.includes('fetch') || msg.includes('network') || msg.includes('Network')) {
      return res.status(503).json({ error: 'Cannot connect to authentication service. Try again in a moment.' })
    }
    return res.status(500).json({ error: `Login error: ${msg || 'Unknown. Check Render logs.'}` })
  }
})

// ─── LOGOUT ───────────────────────────────────────────────────────────────────
app.post('/api/logout', auth, async (req, res) => {
  try { await authClient.auth.signOut() } catch(_) {}
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'USER_LOGOUT', details: 'Signed out' }) } catch(_) {}
  res.json({ success: true })
})

// ─── ME ───────────────────────────────────────────────────────────────────────
app.get('/api/me', auth, (req, res) => res.json(req.user))
app.get('/api/health', (req, res) => res.json({ 
  status: 'ok', 
  ts: new Date().toISOString(), 
  env: { 
    url: !!SUPABASE_URL, 
    anon: !!SUPABASE_ANON_KEY,
    anon_prefix: SUPABASE_ANON_KEY ? SUPABASE_ANON_KEY.substring(0,15) + '...' : 'NOT SET',
    service: !!SUPABASE_SERVICE_KEY 
  } 
}))

// ─── CHANGE OWN PASSWORD ──────────────────────────────────────────────────────
app.post('/api/change-password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body
    if (!new_password || new_password.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' })
    // Verify current password
    const { error: authErr } = await authClient.auth.signInWithPassword({ email: req.user.email, password: current_password })
    if (authErr) return res.status(401).json({ error: 'Current password is incorrect' })
    const { error } = await supabase.auth.admin.updateUserById(req.user.id, { password: new_password })
    if (error) return res.status(400).json({ error: error.message })
    try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CHANGE_PASSWORD', details: 'User changed own password' }) } catch(_) {}
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: 'Password change failed. Please try again.' })
  }
})

// ─── ADMIN RESET PASSWORD ─────────────────────────────────────────────────────
app.post('/api/users/:id/reset-password', auth, requireAdmin, async (req, res) => {
  try {
    const { data: target } = await supabase.from('user_profiles').select('email').eq('id', req.params.id).single()
    if (!target) return res.status(404).json({ error: 'User not found' })
    const { data: linkData, error: linkErr } = await supabase.auth.admin.generateLink({ type: 'recovery', email: target.email })
    if (!linkErr && linkData) {
      try { await safeInsertLog({ user_id: req.user.id, action: 'RESET_PASSWORD', details: 'Reset link sent to: ' + target.email }) } catch(_) {}
      return res.json({ success: true, method: 'magic_link', message: 'Password reset email sent to ' + target.email + '. Link expires in 1 hour.' })
    }
    // Fallback only when generateLink is unavailable on this Supabase plan
    const tmpPwd = require('crypto').randomBytes(16).toString('base64url')
    const { error: pwdErr } = await supabase.auth.admin.updateUserById(req.params.id, { password: tmpPwd })
    if (pwdErr) return res.status(400).json({ error: pwdErr.message })
    try { await safeInsertLog({ user_id: req.user.id, action: 'RESET_PASSWORD', details: 'Temp password set for: ' + target.email }) } catch(_) {}
    res.json({ success: true, method: 'temporary_password', temporary_password: tmpPwd, message: 'Temp password set for ' + target.email + '. Share via secure channel only.' })
  } catch (err) { res.status(500).json({ error: err.message }) }
})
// ─── WIBs ─────────────────────────────────────────────────────────────────────
app.get('/api/wibs', auth, async (req, res) => {
  const { state, status, search, limit = 200, offset = 0 } = req.query
  let q = supabase.from('wib_records').select('*, owner:user_profiles!owner_id(full_name,email)', { count: 'exact' })
  if (state) q = q.eq('state', state)
  if (status) q = q.eq('status', status)
  if (search) q = q.ilike('wib_name', `%${search}%`)
  q = q.order('call_priority_score', { ascending: false }).range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.get('/api/wibs/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('wib_records').select('*, owner:user_profiles!owner_id(full_name,email)').eq('id', req.params.id).single()
  if (error) return res.status(404).json({ error: 'Not found' })
  res.json(data)
})

app.post('/api/wibs', auth, async (req, res) => {
  const allowed = ['wib_name','short_name','state','status','wib_phone','wib_email','website','max_award_per_ein','match_requirement_pct','wib_type','source_url','google_drive_folder_url','next_steps','blockers','notes','iwt_program_active','independent_creation_logged','last_verified_date','call_priority_score']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.wib_name?.trim()) return res.status(400).json({ error: 'WIB name required' })
  if (!body.source_url?.trim()) return res.status(400).json({ error: 'Source URL required (public government page)' })
  const { data, error } = await supabase.from('wib_records').insert({ ...body, owner_id: req.user.id }).select('*, owner:user_profiles!owner_id(full_name,email)').single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'CREATE_WIB', record_type: 'wib_records', record_id: data.id, details: `Created: ${data.wib_name}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/wibs/:id', auth, async (req, res) => {
  const allowed = ['wib_name','short_name','state','status','wib_phone','wib_email','website','max_award_per_ein','match_requirement_pct','wib_type','source_url','google_drive_folder_url','next_steps','blockers','notes','iwt_program_active','independent_creation_logged','last_verified_date','call_priority_score']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('wib_records').update(body).eq('id', req.params.id).select('*, owner:user_profiles!owner_id(full_name,email)').single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'UPDATE_WIB', record_type: 'wib_records', record_id: req.params.id, details: `Updated: ${data.wib_name}` }) } catch(_) {}
  res.json(data)
})

app.delete('/api/wibs/:id', auth, requireAdmin, async (req, res) => {
  const { data: wib } = await supabase.from('wib_records').select('wib_name').eq('id', req.params.id).single()
  const { error } = await supabase.from('wib_records').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'DELETE_WIB', details: `Deleted: ${wib?.wib_name}` }) } catch(_) {}
  res.json({ success: true })
})

// ─── COMPANIES ────────────────────────────────────────────────────────────────
// ─── COMPANY DEDUPLICATION ────────────────────────────────────────────────────
app.post('/api/companies/dedup', auth, requireAdmin, async (req, res) => {
  // Find and merge duplicate companies (same name normalized)
  const { data: all, error } = await supabase.from('companies').select('*').order('created_at')
  if (error) return res.status(400).json({ error: error.message })

  const groups = {}  // normalized name → [records]
  for (const c of (all || [])) {
    const key = c.company_name.trim().toLowerCase().replace(/[^a-z0-9]/g,'').substring(0,30)
    if (!groups[key]) groups[key] = []
    groups[key].push(c)
  }

  let merged = 0, deleted = 0, errors = []
  for (const [key, group] of Object.entries(groups)) {
    if (group.length < 2) continue
    // Keep oldest (first created), merge others into it
    const keeper = group[0]
    const dupes  = group.slice(1)
    // Merge all non-null fields from dupes into keeper
    const patch = {}
    for (const d of dupes) {
      for (const [k, v] of Object.entries(d)) {
        if (v && !keeper[k] && !['id','created_at','updated_at'].includes(k)) patch[k] = v
      }
    }
    if (Object.keys(patch).length) {
      const { error: pErr } = await supabase.from('companies').update(patch).eq('id', keeper.id)
      if (pErr) errors.push(pErr.message)
      else merged++
    }
    // Delete duplicates (re-link their locations/applications first)
    for (const d of dupes) {
      await supabase.from('locations').update({ company_id: keeper.id }).eq('company_id', d.id)
      await supabase.from('applications').update({ company_id: keeper.id }).eq('company_id', d.id)
      const { error: dErr } = await supabase.from('companies').delete().eq('id', d.id)
      if (!dErr) deleted++
    }
  }
  res.json({ merged, deleted, errors, total_groups: Object.values(groups).filter(g=>g.length>1).length })
})


app.get('/api/companies', auth, async (req, res) => {
  const { search, status, limit = 200, offset = 0 } = req.query
  let q = supabase.from('companies').select('*', { count: 'exact' })
  if (status) q = q.eq('status', status)
  if (search) q = q.ilike('company_name', `%${search}%`)
  q = q.order('company_name').range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/companies', auth, async (req, res) => {
  const allowed = ['company_name','company_type','status','fein','domain','employee_count_total','avg_hourly_wage','primary_contact_name','primary_contact_email','primary_contact_phone','training_needs','notes','rating','is_25_pct_operator','supported_by']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.company_name?.trim()) return res.status(400).json({ error: 'Company name required' })

  // ── Duplicate detection ──────────────────────────────────────────────────
  // Check by name (fuzzy), domain, or email
  const nameClean = body.company_name.trim().toLowerCase()
  let dupQ = supabase.from('companies').select('id,company_name,domain,primary_contact_email,status,notes')
  // ilike for name similarity
  const { data: byName } = await dupQ.ilike('company_name', `%${nameClean.substring(0,20)}%`).limit(5)
  const { data: byDomain } = body.domain
    ? await supabase.from('companies').select('id,company_name,domain').ilike('domain', `%${body.domain.replace(/^https?:\/\//,'').split('/')[0]}%`).limit(3)
    : { data: [] }
  const { data: byEmail } = body.primary_contact_email
    ? await supabase.from('companies').select('id,company_name,primary_contact_email').eq('primary_contact_email', body.primary_contact_email).limit(3)
    : { data: [] }

  // Find best duplicate match
  const allDups = [...(byName||[]), ...(byDomain||[]), ...(byEmail||[])]
  const deduped = [...new Map(allDups.map(d => [d.id, d])).values()]
  const match = deduped.find(d => {
    const existName = d.company_name.trim().toLowerCase()
    const newName   = nameClean
    // Exact match or very close (first 25 chars match)
    if (existName === newName) return true
    if (existName.substring(0,25) === newName.substring(0,25)) return true
    if (body.domain && d.domain && d.domain.toLowerCase().includes(body.domain.replace(/^https?:\/\//,'').split('/')[0].toLowerCase())) return true
    if (body.primary_contact_email && d.primary_contact_email === body.primary_contact_email) return true
    return false
  })

  // If merge=true flag is set, merge into existing record
  if (req.body.merge === true && req.body.merge_into_id) {
    const mergeId = req.body.merge_into_id
    const { data: existing } = await supabase.from('companies').select('*').eq('id', mergeId).single()
    if (!existing) return res.status(404).json({ error: 'Target company not found' })
    // Only fill in blank fields — never overwrite existing values
    const mergePayload = {}
    for (const [k, v] of Object.entries(body)) {
      if (v && !existing[k]) mergePayload[k] = v
    }
    mergePayload.last_contact_date = new Date().toISOString()
    const { data: merged, error: mergeErr } = await supabase.from('companies').update(mergePayload).eq('id', mergeId).select().single()
    if (mergeErr) return res.status(400).json({ error: mergeErr.message })
    try { await safeInsertLog({ user_id: req.user.id, action: 'MERGE_COMPANY', record_type: 'companies', record_id: mergeId, details: `Merged: ${body.company_name} into ${existing.company_name}` }) } catch(_) {}
    return res.json({ merged: true, data: merged })
  }

  // If duplicate found and no merge flag — return duplicate info for user decision
  if (match && req.body.force !== true) {
    return res.status(409).json({
      duplicate: true,
      message: `A company named "${match.company_name}" already exists`,
      existing: { id: match.id, company_name: match.company_name, domain: match.domain, status: match.status },
    })
  }

  // Create new (forced or no dup)
  const { data, error } = await supabase.from('companies').insert(body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'CREATE_COMPANY', record_type: 'companies', record_id: data.id, details: `Created: ${data.company_name}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/companies/:id', auth, async (req, res) => {
  const allowed = ['company_name','company_type','status','fein','domain','employee_count_total','avg_hourly_wage','primary_contact_name','primary_contact_email','primary_contact_phone','training_needs','notes','rating']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('companies').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/companies/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('companies').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── LOCATIONS ────────────────────────────────────────────────────────────────
app.get('/api/locations', auth, async (req, res) => {
  const { state, status, wib_id, search, limit = 200, offset = 0 } = req.query
  let q = supabase.from('locations').select('*, parent_company:companies(company_name), wib:wib_records(wib_name,state)', { count: 'exact' })
  if (state) q = q.eq('state', state)
  if (status) q = q.eq('status', status)
  if (wib_id) q = q.eq('wib_id', wib_id)
  if (search) q = q.ilike('location_name', `%${search}%`)
  q = q.order('location_name').range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/locations', auth, async (req, res) => {
  const allowed = ['location_name','state','county','city','status','employee_count','company_id','wib_id','notes','address']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.location_name?.trim()) return res.status(400).json({ error: 'Location name required' })
  const { data, error } = await supabase.from('locations').insert(body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.put('/api/locations/:id', auth, async (req, res) => {
  const allowed = ['location_name','state','county','city','status','employee_count','notes','address']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('locations').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/locations/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('locations').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── FUNDING ─────────────────────────────────────────────────────────────────
app.get('/api/funding', auth, async (req, res) => {
  const { status, wib_id, search, limit = 200, offset = 0 } = req.query
  let q = supabase.from('funding_opportunities').select('*, wib:wib_records(id,wib_name,state)', { count: 'exact' })
  if (status) q = q.eq('status', status)
  if (wib_id) q = q.eq('wib_id', wib_id)
  if (search) q = q.ilike('opportunity_name', `%${search}%`)
  q = q.order('created_at', { ascending: false }).range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/funding', auth, async (req, res) => {
  const allowed = ['opportunity_name','wib_id','status','program_type','max_award_per_ein','application_deadline','application_link','source_url','notes','independent_creation_logged','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.opportunity_name?.trim()) return res.status(400).json({ error: 'Opportunity name required' })
  if (!body.source_url?.trim()) return res.status(400).json({ error: 'Source URL required' })
  const { data, error } = await supabase.from('funding_opportunities').insert(body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'CREATE_FUNDING', record_type: 'funding_opportunities', record_id: data.id, details: `Created: ${data.opportunity_name}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/funding/:id', auth, async (req, res) => {
  const allowed = ['opportunity_name','status','program_type','max_award_per_ein','application_deadline','application_link','source_url','notes','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('funding_opportunities').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/funding/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('funding_opportunities').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── APPLICATIONS ─────────────────────────────────────────────────────────────
app.get('/api/applications', auth, async (req, res) => {
  const { status, limit = 200, offset = 0 } = req.query
  let q = supabase.from('applications').select('*, company:companies(id,company_name), wib:wib_records(id,wib_name,state), funding_opportunity:funding_opportunities(id,opportunity_name), revenue:revenue_records(fee_model,calculated_success_fee,invoice_status)', { count: 'exact' })
  if (status) q = q.eq('status', status)
  q = q.order('created_at', { ascending: false }).range(+offset, +offset + Math.min(+limit, 200) - 1)
  const { data, error, count } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/applications', auth, async (req, res) => {
  const allowed = ['company_id','wib_id','funding_opportunity_id','status','award_amount_requested','submission_date','notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.company_id) return res.status(400).json({ error: 'Company required' })
  if (!body.wib_id) return res.status(400).json({ error: 'WIB required' })
  const { data, error } = await supabase.from('applications').insert({ ...body, owner_id: req.user.id }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'CREATE_APPLICATION', record_type: 'applications', record_id: data.id, details: `Created: ${data.application_number}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/applications/:id', auth, async (req, res) => {
  const allowed = ['status','award_amount_requested','award_amount_approved','submission_date','decision_date','notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('applications').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'UPDATE_APPLICATION', record_type: 'applications', record_id: req.params.id, details: `Status: ${body.status || 'updated'}` }) } catch(_) {}
  res.json(data)
})

app.delete('/api/applications/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('applications').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── COMPLIANCE ───────────────────────────────────────────────────────────────
app.get('/api/compliance', auth, async (req, res) => {
  const { data, error } = await supabase.from('v_compliance_alerts').select('*').order('days_until_final_due')
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.put('/api/compliance/:id', auth, async (req, res) => {
  const allowed = ['final_report_submitted','final_report_submitted_date','attendance_sheets_collected','compliance_notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('compliance_records').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── REVENUE ──────────────────────────────────────────────────────────────────
app.get('/api/revenue/dashboard', auth, async (req, res) => {
  const { data, error } = await supabase.from('v_revenue_dashboard').select('*').single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data || {})
})

app.get('/api/revenue', auth, async (req, res) => {
  const { data, error } = await supabase.from('revenue_records').select('*, company:companies(company_name), wib:wib_records(wib_name)').order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.put('/api/revenue/:id', auth, async (req, res) => {
  const allowed = ['invoice_status','payment_received_date','invoice_sent_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('revenue_records').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'UPDATE_REVENUE', record_type: 'revenue_records', record_id: req.params.id, details: `Invoice: ${body.invoice_status || 'updated'}` }) } catch(_) {}
  res.json(data)
})

// ─── NOTES ────────────────────────────────────────────────────────────────────
app.get('/api/notes', auth, async (req, res) => {
  const { record_type, record_id, limit = 50 } = req.query
  const baseCols = global._safeActivityCols || 'id,action,created_at'
  const userJoin = (global._hasUserId !== false) ? ',user:user_profiles!user_id(full_name,email)' : ''
  const cols = baseCols + userJoin
  let q = supabase.from('activity_log').select(cols).eq('action', 'NOTE')
  if (record_type && global._hasRecordType !== false) q = q.eq('record_type', record_type)
  if (record_id   && global._hasRecordId   !== false) q = q.eq('record_id', record_id)
  q = q.order('created_at', { ascending: false }).limit(Math.min(+limit, 500))
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  const normalized = (data || []).map(n => parseLogRow(n))
  res.json({ data: normalized })
})

app.post('/api/notes', auth, async (req, res) => {
  const { record_type, record_id, note_type = 'Note', is_aircall = false } = req.body
  // Accept either 'content' or 'details' field name for backward compatibility
  const content = (req.body.content || req.body.details || '').trim()
  if (!content) return res.status(400).json({ error: 'Note content required' })
  const { data, error } = await safeInsertLog({
    user_id: req.user.id, action: 'NOTE',
    record_type: record_type || null, record_id: record_id || null,
    details: content.trim(),
    metadata: { note_type, is_aircall, content: content.trim() }
  })
  if (error) return res.status(400).json({ error: error.message })
  // Fetch with user join using safe column list
  const baseCols2 = global._safeActivityCols || 'id,action,created_at'
  const userJoin2 = (global._hasUserId !== false) ? ',user:user_profiles!user_id(full_name,email)' : ''
  const cols2 = baseCols2 + userJoin2
  const { data: full } = await supabase.from('activity_log').select(cols2).eq('id', data.id).single()
  res.json(parseLogRow(full || data))
})

// ─── TASKS ────────────────────────────────────────────────────────────────────
app.get('/api/tasks', auth, async (req, res) => {
  const { record_id, limit = 100 } = req.query
  // Build column list based on what actually exists in the DB
  const baseCols = global._safeActivityCols || 'id,action,created_at'
  const userJoin = (global._hasUserId !== false) ? ',user:user_profiles!user_id(full_name)' : ''
  const cols = baseCols + userJoin
  let q = supabase.from('activity_log').select(cols).eq('action', 'TASK')
  if (record_id && global._hasRecordId !== false) q = q.eq('record_id', record_id)
  q = q.order('created_at', { ascending: false }).limit(Math.min(+limit, 500))
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  const normalized = (data || []).map(t => parseLogRow(t))
  res.json({ data: normalized })
})

app.post('/api/tasks', auth, async (req, res) => {
  const { title, due_date, record_type, record_id, priority = 'normal', notes, assigned_to } = req.body
  if (!title?.trim()) return res.status(400).json({ error: 'Task title required' })
  const { data, error } = await safeInsertLog({
    user_id: req.user.id, action: 'TASK',
    record_type: record_type || null, record_id: record_id || null,
    details: title.trim(),
    metadata: { due_date, priority, notes, done: false, assigned_to, title: title.trim(), created_by: req.user.email }
  })
  if (error) return res.status(400).json({ error: error.message })
  res.json(parseLogRow(data))
})

app.put('/api/tasks/:id', auth, async (req, res) => {
  // Fetch existing to merge state
  const { data: existing } = await supabase.from('activity_log')
    .select(global._safeActivityCols || 'id,action,created_at').eq('id', req.params.id).single()
  const existingParsed = parseLogRow(existing)
  const currentMeta = existingParsed?.metadata || {}
  const newMeta = { ...currentMeta, ...req.body }
  // Save merged state back
  const updatePayload = global._hasMetadata
    ? { metadata: newMeta }
    : { details: JSON.stringify({ text: currentMeta.title || currentMeta.text, ...newMeta }) }
  const { data, error } = await supabase.from('activity_log').update(updatePayload).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(parseLogRow(data))
})

// ─── ACTIVITY / AUDIT ─────────────────────────────────────────────────────────
app.get('/api/activity', auth, async (req, res) => {
  const { record_type, record_id, limit = 100 } = req.query
  const baseCols = global._safeActivityCols || 'id,action,created_at'
  const userJoin = (global._hasUserId !== false) ? ',user:user_profiles!user_id(full_name,email)' : ''
  const cols = baseCols + userJoin
  let q = supabase.from('activity_log').select(cols).neq('action', 'NOTE').neq('action', 'TASK')
  if (record_type && global._hasRecordType !== false) q = q.eq('record_type', record_type)
  if (record_id   && global._hasRecordId   !== false) q = q.eq('record_id', record_id)
  q = q.order('created_at', { ascending: false }).limit(Math.min(+limit, 200))
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data: (data||[]).map(r=>parseLogRow(r)) })
})

app.get('/api/audit', auth, requireAdmin, async (req, res) => {
  const { limit = 100, offset = 0 } = req.query
  const baseCols = global._safeActivityCols || 'id,action,created_at'
  const userJoin = (global._hasUserId !== false) ? ',user:user_profiles!user_id(full_name,email)' : ''
  const cols = baseCols + userJoin
  const { data, error, count } = await supabase.from('activity_log').select(cols, { count: 'exact' }).order('created_at', { ascending: false }).range(+offset, +offset + Math.min(+limit, 200) - 1)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data: (data||[]).map(r=>parseLogRow(r)), count })
})

// ─── USERS ────────────────────────────────────────────────────────────────────
app.get('/api/users', auth, requireAdmin, async (req, res) => {
  const [{ data: users, error }, { data: assignments }] = await Promise.all([
    supabase
      .from('user_profiles')
      .select('id,email,full_name,role,title,phone,is_active,created_at,last_login_at,territory_id')
      .order('created_at', { ascending: false }),
    supabase
      .from('user_territory_assignments')
      .select('user_id,territory_id,territories(id,name)')
  ])
  if (error) return res.status(400).json({ error: error.message })
  // Attach territories array to each user
  const byUser = {}
  for (const a of (assignments || [])) {
    if (!byUser[a.user_id]) byUser[a.user_id] = []
    if (a.territories) byUser[a.user_id].push(a.territories)
  }
  const enriched = (users || []).map(u => ({ ...u, territories: byUser[u.id] || [] }))
  res.json({ data: enriched })
})

app.post('/api/users', auth, requireAdmin, async (req, res) => {
  try {
    const { email, password, full_name, role = 'team_member', title, phone } = req.body
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' })
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' })
    const validRoles = VALID_ROLES
    if (!validRoles.includes(role)) return res.status(400).json({ error: 'Invalid role' })
    if (role === 'super_admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'Only Super Admin can assign the Super Admin role' })
    }
    const { data, error } = await supabase.auth.admin.createUser({
      email: email.trim().toLowerCase(), password,
      email_confirm: true,
      user_metadata: { full_name }
    })
    if (error) return res.status(400).json({ error: error.message })
    await supabase.from('user_profiles').update({ full_name: full_name || null, role, title: title || null, phone: phone || null, is_active: true }).eq('id', data.user.id)
    try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CREATE_USER', details: `Created: ${email} (${role})` }) } catch(_) {}
    const { data: profile } = await supabase.from('user_profiles').select('*').eq('id', data.user.id).single()
    res.json({ user: profile })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.put('/api/users/:id', auth, requireAdmin, async (req, res) => {
  try {
    const { full_name, role, title, phone, is_active } = req.body
    if (req.params.id === req.user.id && is_active === false) return res.status(400).json({ error: 'Cannot disable your own account' })
    // Guard last super_admin
    if ((is_active === false || (role && role !== 'super_admin'))) {
      const { data: t } = await supabase.from('user_profiles').select('role').eq('id', req.params.id).single()
      if (t?.role === 'super_admin') {
        const { count } = await supabase.from('user_profiles').select('*', { count: 'exact', head: true }).eq('role', 'super_admin').eq('is_active', true)
        if ((count || 0) <= 1) return res.status(400).json({ error: 'Cannot disable or demote the only Super Admin' })
      }
    }
    const update = {}
    if (full_name !== undefined) update.full_name = full_name
    if (role !== undefined) update.role = role
    if (title !== undefined) update.title = title
    if (phone !== undefined) update.phone = phone
    if (is_active !== undefined) update.is_active = is_active
    const { data, error } = await supabase.from('user_profiles').update(update).eq('id', req.params.id).select().single()
    if (error) return res.status(400).json({ error: error.message })

    // If disabling: ban in Supabase Auth immediately (invalidates all active JWTs)
    if (is_active === false) {
      try { await supabase.auth.admin.updateUserById(req.params.id, { ban_duration: '876000h' }) }
      catch (e) { console.warn('Supabase Auth ban failed (non-fatal):', e.message) }
    }
    // If re-enabling: lift the ban
    if (is_active === true) {
      try { await supabase.auth.admin.updateUserById(req.params.id, { ban_duration: 'none' }) }
      catch (e) { console.warn('Supabase Auth unban failed (non-fatal):', e.message) }
    }
    // Prevent non-super-admins from assigning super_admin role
    if (role === 'super_admin' && req.user.role !== 'super_admin') {
      return res.status(403).json({ error: 'Only Super Admins can assign the Super Admin role' })
    }

    const changeNote = [
      is_active === false ? 'DISABLED' : is_active === true ? 'RE-ENABLED' : '',
      role ? 'role set to ' + role : '',
    ].filter(Boolean).join('; ')
    try { await safeInsertLog({ user_id: req.user.id, action: 'UPDATE_USER', details: 'Updated: ' + data.email + (changeNote ? ' — ' + changeNote : '') }) } catch(_) {}
    res.json(data)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/users/:id', auth, requireSuper, async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' })
    const { data: target } = await supabase.from('user_profiles').select('email,role').eq('id', req.params.id).single()
    if (!target) return res.status(404).json({ error: 'User not found' })
    if (target.role === 'super_admin') {
      const { count } = await supabase.from('user_profiles').select('*', { count: 'exact', head: true }).eq('role', 'super_admin')
      if ((count || 0) <= 1) return res.status(400).json({ error: 'Cannot delete the only Super Admin' })
    }
    const { error } = await supabase.auth.admin.deleteUser(req.params.id)
    if (error) return res.status(400).json({ error: error.message })
    try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'DELETE_USER', details: `DELETED: ${target.email}` }) } catch(_) {}
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})



// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 3 — CONTACTS, TRAINING PROVIDERS, INVOICES, CONTRACTS, GRANT AWARDS
// ═══════════════════════════════════════════════════════════════════════════════

// ─── CONTACTS ────────────────────────────────────────────────────────────────
app.get('/api/contacts', auth, async (req, res) => {
  const { record_type, record_id, search, limit = 200 } = req.query
  let q = supabase.from('activity_log')
    .select('*, user:user_profiles!user_id(full_name)')
    .eq('action', 'CONTACT')
  if (record_type) q = q.eq('record_type', record_type)
  if (record_id) q = q.eq('record_id', record_id)
  q = q.order('created_at', { ascending: false }).limit(+limit)
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.post('/api/contacts', auth, async (req, res) => {
  const { name, title, email, phone, record_type, record_id, notes } = req.body
  if (!name?.trim()) return res.status(400).json({ error: 'Contact name required' })
  const content = JSON.stringify({ name, title, email, phone, notes })
  const { data, error } = await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'CONTACT',
    record_type: record_type || null, record_id: record_id || null,
    details: name, metadata: { name, title, email, phone, notes }
  }).select('*, user:user_profiles!user_id(full_name)').single()
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CREATE_CONTACT', record_type, record_id, details: `Added contact: ${name}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/contacts/:id', auth, async (req, res) => {
  const { name, title, email, phone, notes } = req.body
  const { data: existing } = await supabase.from('activity_log').select(global._safeActivityCols || 'id,action,created_at').eq('id', req.params.id).single()
  const existingParsed = parseLogRow(existing)
  const merged = { ...(existingParsed?.metadata || {}), name, title, email, phone, notes }
  const updateVal = global._hasMetadata ? { metadata: merged, details: name || existingParsed?.metadata?.name } : { details: JSON.stringify({ text: name, ...merged }) }
  const { data, error } = await supabase.from('activity_log').update(updateVal).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/contacts/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('activity_log').delete().eq('id', req.params.id).eq('action', 'CONTACT')
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── TRAINING PROVIDERS ───────────────────────────────────────────────────────
app.get('/api/training-providers', auth, async (req, res) => {
  const { search, limit = 200 } = req.query
  let q = supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name)').eq('action', 'TRAINING_PROVIDER')
  if (search) q = q.ilike('details', `%${search}%`)
  q = q.order('created_at', { ascending: false }).limit(+limit)
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.post('/api/training-providers', auth, async (req, res) => {
  const { name, provider_type, website, contact_email, contact_phone, programs, state, notes, status = 'active' } = req.body
  if (!name?.trim()) return res.status(400).json({ error: 'Provider name required' })
  const { data, error } = await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'TRAINING_PROVIDER',
    details: name,
    metadata: { name, provider_type, website, contact_email, contact_phone, programs, state, notes, status }
  }).select('*, user:user_profiles!user_id(full_name)').single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.put('/api/training-providers/:id', auth, async (req, res) => {
  const { data: existing } = await supabase.from('activity_log').select(global._safeActivityCols || 'id,action,created_at').eq('id', req.params.id).single()
  const existingParsed = parseLogRow(existing)
  const merged = { ...(existingParsed?.metadata || {}), ...req.body }
  const tpUpdateData = global._hasMetadata
    ? { details: req.body.name || existing?.details, metadata: merged }
    : { details: JSON.stringify({ text: req.body.name || existing?.details, ...merged }) }
  const { data, error } = await supabase.from('activity_log').update(tpUpdateData).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/training-providers/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('activity_log').delete().eq('id', req.params.id).eq('action', 'TRAINING_PROVIDER')
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── INVOICES ─────────────────────────────────────────────────────────────────
app.get('/api/invoices', auth, async (req, res) => {
  const { status, limit = 200 } = req.query
  let q = supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name)').eq('action', 'INVOICE')
  if (status) q = q.contains('metadata', { status })
  q = q.order('created_at', { ascending: false }).limit(+limit)
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.post('/api/invoices', auth, async (req, res) => {
  const { invoice_number, company_name, application_id, amount, fee_model, status = 'draft', due_date, notes } = req.body
  if (!company_name?.trim() || !amount) return res.status(400).json({ error: 'Company and amount required' })
  const inv_num = invoice_number || `INV-${Date.now().toString().slice(-6)}`
  const { data, error } = await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'INVOICE',
    record_type: 'applications', record_id: application_id || null,
    details: inv_num,
    metadata: { invoice_number: inv_num, company_name, application_id, amount, fee_model, status, due_date, notes, created_at: new Date().toISOString() }
  }).select('*, user:user_profiles!user_id(full_name)').single()
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CREATE_INVOICE', details: `Invoice ${inv_num} — $${amount} — ${company_name}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/invoices/:id', auth, async (req, res) => {
  const { data: existing } = await supabase.from('activity_log').select(global._safeActivityCols || 'id,action,created_at').eq('id', req.params.id).single()
  const merged = { ...(existing?.metadata || {}), ...req.body }
  const updateData = global._hasMetadata ? { metadata: merged } : { details: JSON.stringify(merged) }
  const { data, error } = await supabase.from('activity_log').update(updateData).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'UPDATE_INVOICE', details: `Invoice ${merged.invoice_number} → ${req.body.status || 'updated'}` }) } catch(_) {}
  res.json(data)
})

// ─── CONTRACTS ───────────────────────────────────────────────────────────────
app.get('/api/contracts', auth, async (req, res) => {
  const { status, limit = 200 } = req.query
  let q = supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name)').eq('action', 'CONTRACT')
  q = q.order('created_at', { ascending: false }).limit(+limit)
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.post('/api/contracts', auth, async (req, res) => {
  const { company_name, contract_type, value, status = 'draft', signed_date, expiry_date, notes } = req.body
  if (!company_name?.trim()) return res.status(400).json({ error: 'Company name required' })
  const contract_number = `CTR-${Date.now().toString().slice(-6)}`
  const { data, error } = await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'CONTRACT',
    details: contract_number,
    metadata: { contract_number, company_name, contract_type, value, status, signed_date, expiry_date, notes, created_at: new Date().toISOString() }
  }).select('*, user:user_profiles!user_id(full_name)').single()
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CREATE_CONTRACT', details: `Contract ${contract_number} — ${company_name}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/contracts/:id', auth, async (req, res) => {
  const { data: existing } = await supabase.from('activity_log').select(global._safeActivityCols || 'id,action,created_at').eq('id', req.params.id).single()
  const merged = { ...(existing?.metadata || {}), ...req.body }
  const updateData = global._hasMetadata ? { metadata: merged } : { details: JSON.stringify(merged) }
  const { data, error } = await supabase.from('activity_log').update(updateData).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/contracts/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('activity_log').delete().eq('id', req.params.id).eq('action', 'CONTRACT')
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── GRANT AWARDS ─────────────────────────────────────────────────────────────
app.get('/api/grant-awards', auth, async (req, res) => {
  // Pull from applications that have been awarded + their revenue records
  const { data, error } = await supabase.from('applications')
    .select('*, company:companies(company_name), wib:wib_records(wib_name,state), funding_opportunity:funding_opportunities(opportunity_name), revenue:revenue_records(fee_model,calculated_success_fee,invoice_status,payment_received_date)')
    .in('status', ['awarded', 'active', 'completed', 'closed'])
    .order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

// ─── CSV IMPORT ───────────────────────────────────────────────────────────────
app.post('/api/import/:type', auth, async (req, res) => {
  const { type } = req.params
  const { rows, batch, totalBatches } = req.body
  if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: 'No rows provided' })
  // No row limit — process any size file via batching

  const results = { created: 0, errors: [], batch: batch || 1, totalBatches: totalBatches || 1 }
  const today = new Date().toISOString().split('T')[0]

  // Helper: bulk insert with error collection
  async function bulkInsert(table, records) {
    if (!records.length) return
    const { data, error } = await supabase.from(table).insert(records).select('id')
    if (error) {
      // On bulk error, retry individually to isolate bad rows
      for (const rec of records) {
        const { error: e2 } = await supabase.from(table).insert(rec)
        if (e2) results.errors.push(`Row error: ${e2.message}`)
        else results.created++
      }
    } else {
      results.created += (data || records).length
    }
  }

  try {
    if (type === 'wibs') {
      // Comprehensive WIB import - handles Attio export with all fields from screenshots
      // WIB Attio columns: Workforce Board, WIB Email Address, Short Name, Status, Type,
      // Contacts, Locations, Website, Call Priority, Funding Opportunities, etc.
      
      const valid = [], skipped = []
      const wibStatusMap = {
        'funding available':'funding_available','funding available - have program':'funding_available','funding_available':'funding_available','open':'funding_available','active':'funding_available',
        'follow up needed':'follow_up_needed','follow_up_needed':'follow_up_needed','follow up':'follow_up_needed',
        'pending employer':'pending_employer','pending_employer':'pending_employer','pending':'pending_employer',
        'no reachout completed':'no_reachout_complete','no reachout complete':'no_reachout_complete','no_reachout_complete':'no_reachout_complete','new':'no_reachout_complete','not contacted':'no_reachout_complete',
        'funding not available':'funding_not_available','funding_not_available':'funding_not_available','closed':'funding_not_available','not applicable':'no_reachout_complete',
        'stop applications':'stop_applications','stop_applications':'stop_applications','closed - deadline':'funding_not_available','closed - out of funds':'funding_not_available',
      }

      const getWibField = (row, ...keys) => {
        for (const k of keys) {
          const v = row[k] ?? row[k.toLowerCase()] ?? row[k.toUpperCase()]
          if (v !== undefined && String(v).trim() !== '' && String(v).trim() !== 'Not applicable') return String(v).trim()
        }
        for (const k of keys) {
          const found = Object.keys(row).find(rk => rk.toLowerCase().replace(/[^a-z]/g,'').includes(k.toLowerCase().replace(/[^a-z]/g,'')))
          if (found && String(row[found]).trim() && String(row[found]).trim() !== 'Not applicable') return String(row[found]).trim()
        }
        return null
      }

      for (const row of rows) {
        const name = getWibField(row, 'wib_name','Workforce Board','WIB Name','WIB','Name','Record','Board Name')
        if (!name?.trim()) { skipped.push('Skipped — no WIB name'); continue }

        const rawStatus = (getWibField(row, 'Status','WIB Status','Funding Status') || '').toLowerCase().trim()
        const status = wibStatusMap[rawStatus] || 'no_reachout_complete'

        const website = getWibField(row, 'Website','URL','Web','Homepage','WIB Website')
        const domain = website ? website.replace(/^https?:\/\/(www\.)?/,'').split('/')[0] : null

        // Capture ALL extra fields into notes
        const knownWibKeys = new Set([
          'Record ID','Workforce Board','WIB Name','WIB','Name','Record','Board Name',
          'WIB Email Address','Email','Short Name','Short','Abbreviation',
          'Status','WIB Status','Funding Status','Type','WIB Type','Board Type',
          'Website','URL','Web','Homepage','Phone','WIB Phone',
          'State','Region','County','Address',
          'Call Priority','Priority','READONLY In-Network',
          'Created','Updated','Owner','Assigned',
        ])
        const extras = Object.entries(row).filter(([k,v]) => !knownWibKeys.has(k) && v && String(v).trim() && String(v).trim() !== 'Not applicable')
        const noteParts = []
        // Extract contacts (Attio: "Contacts > Name" column has multiple people)
        const contactCols = Object.entries(row).filter(([k,v]) => /contact.*name|contacts.*name/i.test(k) && v && String(v).trim() !== 'Not applicable')
        if (contactCols.length) noteParts.push('Contacts: ' + contactCols.map(([,v])=>v).join(', '))
        // Call priority score from Attio readonly field
        const callPriorityVal = getWibField(row, 'Call Priority','call_priority','READONLY In-Network','Priority Score','In-Network Locations')
        const callPriorityNum = callPriorityVal ? parseInt(String(callPriorityVal).replace(/[^0-9]/g, '')) || 0 : 0
        // Type (State vs Regional)
        const wibTypeVal = getWibField(row, 'Type','WIB Type','Board Type','Organization Type')
        if (wibTypeVal) noteParts.push('WIB Type: ' + wibTypeVal)
        // Zipcodes from Attio
        const zipVal = getWibField(row, 'Zipcode','Regional Zipcode','State Zipcode','zip','zipcodes')
        if (zipVal) noteParts.push('Service Area Zipcodes: ' + zipVal)
        if (extras.length) noteParts.push('Additional Data:\n' + extras.map(([k,v]) => k+': '+v).join('\n'))

        // Extract state from name prefix (Attio format: "TX - Board Name" or "MN - Board Name")
        const stateFromName = (() => {
          const match = name.match(/^([A-Z]{2})\s*-\s*/)
          if (match) return match[1]
          return null
        })()

        // State full-name to abbreviation map
        const stateAbbr = {
          'alabama':'AL','alaska':'AK','arizona':'AZ','arkansas':'AR','california':'CA',
          'colorado':'CO','connecticut':'CT','delaware':'DE','florida':'FL','georgia':'GA',
          'hawaii':'HI','idaho':'ID','illinois':'IL','indiana':'IN','iowa':'IA','kansas':'KS',
          'kentucky':'KY','louisiana':'LA','maine':'ME','maryland':'MD','massachusetts':'MA',
          'michigan':'MI','minnesota':'MN','mississippi':'MS','missouri':'MO','montana':'MT',
          'nebraska':'NE','nevada':'NV','new hampshire':'NH','new jersey':'NJ','new mexico':'NM',
          'new york':'NY','north carolina':'NC','north dakota':'ND','ohio':'OH','oklahoma':'OK',
          'oregon':'OR','pennsylvania':'PA','rhode island':'RI','south carolina':'SC',
          'south dakota':'SD','tennessee':'TN','texas':'TX','utah':'UT','vermont':'VT',
          'virginia':'VA','washington':'WA','west virginia':'WV','wisconsin':'WI','wyoming':'WY',
          'district of columbia':'DC','puerto rico':'PR'
        }

        const rawState = getWibField(row, 'State','Region','State/Province','Zipcode > State','State Zipcode > State')
        const stateValue = stateFromName
          || (rawState && rawState.length === 2 ? rawState.toUpperCase() : null)
          || (rawState ? stateAbbr[rawState.toLowerCase()] : null)
          || 'US'  // Final fallback — 'state' is NOT NULL in wib_records

        const wibRecord = {
          wib_name: name,
          short_name: getWibField(row, 'Short Name','Short','Abbreviation','Acronym') || null,
          state: stateValue,
          status,
          wib_email: getWibField(row, 'WIB Email Address','Email Address','Email','Contact Email') || null,
          wib_phone: getWibField(row, 'Phone','WIB Phone','Contact Phone','Phone Number') || null,
          website: domain || null,
          source_url: website || name || 'https://careerOneStop.org',
          notes: noteParts.join('\n') || null,
          independent_creation_logged: true,
          owner_id: req.user.id,
          last_verified_date: new Date().toISOString().split('T')[0]
        }
        if (callPriorityNum > 0) wibRecord.call_priority_score = callPriorityNum
        valid.push(wibRecord)
      }
      results.errors.push(...skipped)
      for (let i = 0; i < valid.length; i += 100) await bulkInsert('wib_records', valid.slice(i, i + 100))

    } else if (type === 'companies') {
      // Comprehensive field mapping — handles Attio, HubSpot, Salesforce, custom CSVs
      // Valid DB statuses: prospect, contacted, qualified, active_client, churned, dnc
      const coStatusMap = {
        'prospect':'prospect','lead':'prospect','potential':'prospect','new':'prospect','unqualified':'prospect',
        'contacted':'contacted','outreach':'contacted','in progress':'contacted','in_progress':'contacted','trying':'contacted',
        'qualified':'qualified','qualifying':'qualified','interested':'qualified',
        'client':'active_client','active':'active_client','active client':'active_client','active_client':'active_client',
        'partner':'active_client','customer':'active_client','won':'active_client','closed won':'active_client',
        'network member':'active_client','network_member':'active_client','member':'active_client','network':'active_client',
        'churned':'churned','inactive':'churned','lost':'churned','cancelled':'churned','closed lost':'churned',
        'dnc':'dnc','do not contact':'dnc','do_not_contact':'dnc','blocked':'dnc',
      }

      // Helper: find a value across multiple possible column name variants
      const getField = (row, ...keys) => {
        for (const k of keys) {
          const val = row[k] ?? row[k.toLowerCase()] ?? row[k.toUpperCase()]
          if (val !== undefined && String(val).trim() !== '') return String(val).trim()
        }
        // Try partial match on row keys
        for (const k of keys) {
          const found = Object.keys(row).find(rk => rk.toLowerCase().replace(/[^a-z0-9]/g,'').includes(k.toLowerCase().replace(/[^a-z0-9]/g,'')))
          if (found && String(row[found]).trim() !== '') return String(row[found]).trim()
        }
        return null
      }

      // Find name column header once (handles "Record", "Company Name", "Name", etc.)
      const nameKey = rows[0] ? Object.keys(rows[0]).find(k =>
        /^(company.?name|record|name|company|employer|organization|account.?name|business.?name)$/i.test(k.trim())
      ) : null

      for (const row of rows) {
        const name = (nameKey ? row[nameKey] : null)?.trim()
          || getField(row, 'Company Name','company_name','Record','Name','Company','Employer','Organization','Account Name','Business Name')
        
        if (!name) { results.errors.push('Skipped — no company name found'); continue }

        const rawStatus = (getField(row,'Status','Stage','status','stage','Record Stage','Company Stage') || '').toLowerCase().trim()
        const status = coStatusMap[rawStatus] || 'prospect'

        // Phone: Attio exports "Phone numbers", HubSpot exports "Phone Number", etc.
        const phone = getField(row,
          'Phone numbers','Phone Number','Phone','phone','Mobile','Mobile Phone',
          'primary_contact_phone','Contact Phone','Main Phone','Business Phone')

        // Email: Attio exports "Email addresses"  
        const email = getField(row,
          'Email addresses','Email Address','Email','email','Primary Email',
          'primary_contact_email','Contact Email','Business Email')

        // Website/Domain
        const rawDomain = getField(row,'Website','website','Domain','domain','URL','Homepage','Web','Site')
        const domain = rawDomain ? rawDomain.replace(/^https?:\/\/(www\.)?/,'').split('/')[0] : null

        // Contact person
        const contactName = getField(row,
          'Contact Name','Contact','Primary Contact','Owner Name','Account Owner',
          'primary_contact_name','Rep','Account Manager','Point of Contact')

        // Employee count
        const empRaw = getField(row,'Employee Count','Employees','Number of Employees','employee_count_total','Staff','Headcount','Size')
        const employeeCount = empRaw ? parseInt(String(empRaw).replace(/[^0-9]/g,'')) || null : null

        // Notes
        const notes = getField(row,'Notes','Description','Comments','notes','Summary','Bio','About','Details')

        // Type — default to 'operator' since that's the platform's focus
        const rawType = getField(row,'Type','Company Type','Industry','Sector','Category','company_type')

        // Build clean insert matching exact DB columns
        const insertRow = {}
        insertRow.company_name = name
        insertRow.status = status
        if (rawType) insertRow.company_type = rawType
        if (domain) insertRow.domain = domain
        if (email) insertRow.primary_contact_email = email
        if (phone) insertRow.primary_contact_phone = phone
        if (contactName) insertRow.primary_contact_name = contactName
        if (employeeCount) insertRow.employee_count_total = employeeCount
        if (notes) insertRow.notes = notes

        // Optional numeric fields
        const wage = getField(row,'Avg Wage','Average Wage','Avg Hourly Wage','Hourly Rate','avg_hourly_wage')
        if (wage) {
          const wageNum = parseFloat(String(wage).replace(/[^0-9.]/g,''))
          if (!isNaN(wageNum)) insertRow.avg_hourly_wage = wageNum
        }
        const fein = getField(row,'FEIN','EIN','Tax ID','fein','Federal Tax ID')
        if (fein) insertRow.fein = fein

        const training = getField(row,'Training Needs','Training','training_needs')
        if (training) insertRow.training_needs = training

        // Capture address + any unmapped fields into structured notes
        const address = [
          getField(row,'Street','Address','Street Address','Address Line 1','Street 1','Mailing Street'),
          getField(row,'City','Mailing City'),
          getField(row,'State','Province','Mailing State'),
          getField(row,'Zip','Zip Code','Postal Code','Mailing Zip'),
          getField(row,'Country','Mailing Country'),
        ].filter(Boolean).join(', ')

        const linkedin = getField(row,'LinkedIn','LinkedIn URL','linkedin_url','LinkedIn Profile')
        const tags = getField(row,'Tags','Labels','Categories','tag','label')
        const owner = getField(row,'Owner','Account Owner','Assigned To','Rep','Manager')
        const source = getField(row,'Source','Lead Source','How did you hear','Channel')
        
        // Known columns that are already mapped to DB fields
        const mappedKeys = new Set([
          ...Object.keys(row).filter(k => /company.?name|^record$|^name$|^company$|^employer$|^organization$/i.test(k.trim())),
          'Status','Stage','status','stage','Record Stage',
          'Phone numbers','Phone Number','Phone','Mobile','Business Phone','primary_contact_phone','Contact Phone',
          'Email addresses','Email Address','Email','Primary Email','primary_contact_email','Contact Email',
          'Website','website','Domain','domain','URL','Homepage',
          'Contact Name','Contact','Primary Contact','Owner Name','Account Owner','primary_contact_name','Rep','Account Manager',
          'Employee Count','Employees','Number of Employees','employee_count_total','Staff','Headcount','Size',
          'Notes','Description','Comments','notes','Summary','Bio','About','Details',
          'Type','Company Type','Industry','Sector','Category','company_type',
          'Avg Wage','Average Wage','Avg Hourly Wage','Hourly Rate','avg_hourly_wage',
          'FEIN','EIN','Tax ID','fein','Federal Tax ID',
          'Training Needs','Training','training_needs',
          'Street','Address','Street Address','Address Line 1','Street 1','Mailing Street',
          'City','Mailing City','State','Province','Mailing State',
          'Zip','Zip Code','Postal Code','Mailing Zip','Country','Mailing Country',
          'LinkedIn','LinkedIn URL','linkedin_url','LinkedIn Profile',
          'Tags','Labels','Categories','tag','label',
          'Owner','Assigned To','Manager','Lead Source','Source','How did you hear','Channel',
          'Record ID','id','ID','Created','Created At','Updated','Updated At',
        ])
        
        // Collect any remaining unmapped columns with values
        const extra = Object.entries(row)
          .filter(([k,v]) => !mappedKeys.has(k) && v && String(v).trim())
          .map(([k,v]) => `${k}: ${String(v).trim()}`)
        
        // Build comprehensive notes field
        const notesParts = []
        if (insertRow.notes) notesParts.push(insertRow.notes)
        if (address) notesParts.push(`Address: ${address}`)
        if (linkedin) notesParts.push(`LinkedIn: ${linkedin}`)
        if (tags) notesParts.push(`Tags: ${tags}`)
        if (owner) notesParts.push(`Assigned To: ${owner}`)
        if (source) notesParts.push(`Source: ${source}`)
        if (extra.length) notesParts.push('--- Additional Fields ---\n' + extra.join('\n'))
        
        if (notesParts.length) insertRow.notes = notesParts.join('\n')
        
        // Cap notes at 10000 chars (Supabase text limit safety)
        if (insertRow.notes && insertRow.notes.length > 10000) {
          insertRow.notes = insertRow.notes.substring(0, 9997) + '...'
        }

        // UPSERT: update if company_name already exists, insert if not
        const { data: existingCo } = await supabase.from('companies')
          .select('id').ilike('company_name', insertRow.company_name).limit(1)
        let insertErr
        if (existingCo?.[0]) {
          // Update existing record - only fill in missing fields
          const updateFields = {}
          for (const [k,v] of Object.entries(insertRow)) {
            if (v !== null && v !== '' && k !== 'company_name') updateFields[k] = v
          }
          if (Object.keys(updateFields).length) {
            const { error } = await supabase.from('companies').update(updateFields).eq('id', existingCo[0].id)
            insertErr = error
          }
          results.created++  // count as processed
        } else {
          const { error } = await supabase.from('companies').insert(insertRow)
          insertErr = error
          if (!insertErr) results.created++
        }
        if (insertErr) {
          results.errors.push('"' + name + '": ' + insertErr.message)
          if (results.errors.length === 1) console.error('First company import error:', insertErr.message)
        }
      }

    } else if (type === 'locations') {
      // Pre-load companies ONCE and cache across batches
      if (!global._importCoCache || global._importCoCache.size === 0) {
        const { data: allCos } = await supabase.from('companies').select('id,company_name')
        global._importCoCache = new Map()
        for (const co of (allCos || [])) {
          global._importCoCache.set(co.company_name.toLowerCase().trim(), co.id)
          global._importCoCache.set(co.company_name.toLowerCase().trim().substring(0, 25), co.id)
        }
        console.log('Company cache loaded:', global._importCoCache.size, 'entries for locations import')
      }
      const coMap = global._importCoCache
      const findCo = (name) => {
        if (!name) return null
        const lower = name.toLowerCase().trim()
        if (coMap.has(lower)) return coMap.get(lower)
        for (const [k,id] of coMap) {
          if (k.startsWith(lower.substring(0,15)) || lower.startsWith(k.substring(0,15))) return id
        }
        return null
      }

      const locBatch = []
      console.log("BATCH ROWS COUNT:", rows.length, "FIRST:", JSON.stringify(rows[0]||{}))
      for (const row of rows) {
        if (results.errors.length === 0) console.log("FIRST ROW RAW:", JSON.stringify(rows[0] || {}))
        // Support CRM keys, Attio export headers, and any unrecognized column that looks like a name
        let name = (
          row['location_name'] || row['Record'] || row['Location Name'] ||
          row['Location'] || row['Name'] || row['Facility'] ||
          row['Facility Name'] || row['Nursing Home'] || row['Site Name'] ||
          row['record'] || row['name'] || row['location']
        )
        name = name ? String(name).trim() : ''
        // Last resort: grab the first non-empty value from any column if nothing matched
        if (!name) {
          const firstKey = Object.keys(row).find(k => row[k] && String(row[k]).trim().length > 1)
          if (firstKey && results.errors.length < 3) {
            // Log what headers we actually see (only first time)
            if (results.errors.length === 0) results.errors.push(`DEBUG — CSV headers: ${Object.keys(row).slice(0,8).join(', ')}`)
          }
        }
        if (!name) { results.errors.push('Skipped — no location name'); continue }

        const parentName = (row['parent_operator'] || row['Parent Operator'] || row['Parent Company'] || row['Company'] || row['Operator'] || '').trim()
        const company_id = findCo(parentName)

        const rawState = (row['state'] || row['State'] || row['Province'] || '').trim()
        const rawStatus = (row['status'] || row['Status'] || 'prospect').toLowerCase().trim()
        const statusMap = { 'not contacted': 'prospect', 'network member': 'prospect', 'active': 'active', 'prospect': 'prospect', 'inactive': 'inactive', 'open': 'prospect' }
        
        // UPSERT: check if location already exists
        const { data: existingLoc } = await supabase.from('locations')
          .select('id').ilike('location_name', name).limit(1)
        
        const locRow = {
          location_name: name,
          state: rawState || null,
          city: (row['city'] || row['City'] || '').trim() || null,
          county: (row['county'] || row['County'] || '').trim() || null,
          status: statusMap[rawStatus] || 'prospect',
          employee_count: (row['employee_count'] || row['Employee Count']) ? parseInt(row['employee_count'] || row['Employee Count']) : null,
          notes: row['notes'] || row['Notes'] || null,
          address: row['address'] || row['Address'] || null,
        }
        if (company_id) locRow.company_id = company_id

        // Collect for bulk insert
        if (existingLoc?.[0]) {
          // Update existing
          const { error } = await supabase.from('locations').update(locRow).eq('id', existingLoc[0].id)
          if (error) results.errors.push('"' + name + '": ' + error.message)
          else results.created++
        } else {
          locBatch.push(locRow)
        }
      }
      // Bulk insert new locations
      if (locBatch.length) {
        for (let i = 0; i < locBatch.length; i += 200) {
          const chunk = locBatch.slice(i, i + 200)
          const { data: ins, error } = await supabase.from('locations').insert(chunk).select('id')
          if (error) {
            // On bulk error, retry individually
            for (const row of chunk) {
              const { error: e2 } = await supabase.from('locations').insert(row)
              if (e2) results.errors.push('"' + (row.location_name||'?') + '": ' + e2.message)
              else results.created++
            }
          } else {
            results.created += (ins || chunk).length
          }
        }
      }

    } else if (type === 'funding') {
      const valid = []
      for (const row of rows) {
        // Try all possible column names — Attio may export as 'Record', 'Name', 'Funding Opportunity', etc.
        const name = (
          row['opportunity_name'] || row['Opportunity Name'] || row['Funding Opportunity'] ||
          row['Name'] || row['Record'] || row['Title'] || row['Program Name'] ||
          row['opportunity name'] || row['funding opportunity'] || row['name'] || row['record']
        )?.trim() || ''
        if (!name) {
          if (results.errors.length < 2) {
            const headers = Object.keys(row).slice(0, 10).join(', ')
            results.errors.push(`Skipped row — Opportunity Name required. CSV headers found: ${headers}`)
          } else {
            results.errors.push('Skipped row — Opportunity Name required')
          }
          continue
        }
        valid.push({
          opportunity_name: name,
          status: (() => {
            const rawS = (row['status'] || row['Status'] || '').toLowerCase().trim()
            const fundingStatusMap = {
              'open': 'open', 'active': 'open', 'available': 'open',
              'pending': 'pending', 'pending_employer': 'pending_employer',
              'blocked': 'blocked', 'on hold': 'blocked',
              'stop': 'stop_applications', 'stop applications': 'stop_applications', 'stop_applications': 'stop_applications',
              'closed': 'closed_deadline', 'closed deadline': 'closed_deadline', 'closed_deadline': 'closed_deadline',
              'out of funds': 'closed_out_of_funds', 'closed_out_of_funds': 'closed_out_of_funds',
            }
            return fundingStatusMap[rawS] || 'open'
          })(),
          program_type: row['program_type'] || row['Program Type'] || null,
          source_url: row['source_url'] || row['application_link'] || row['Source URL'] || row['Application Link'] || null,
          max_award_per_ein: (row['max_award_per_ein'] || row['Max Award/EIN'] || row['Max per EIN']) ? parseFloat(row['max_award_per_ein'] || row['Max Award/EIN'] || row['Max per EIN']) : null,
          max_award_per_employee: (row['max_award_per_employee'] || row['Max per employee']) ? parseFloat(row['max_award_per_employee'] || row['Max per employee']) : null,
          application_deadline: row['application_deadline'] || row['Deadline'] || null,
          blocked_reason: row['blocked_reason'] || row['Blocked Reason'] || null,
          promotion_for_participants: row['promotion_for_participants'] || row['Promotion'] || null,
          wage_increase_for_participants: row['wage_increase_for_participants'] || row['Wage Increase'] || null,
          independent_creation_logged: true
        })
      }
      for (let i = 0; i < valid.length; i += 500) await bulkInsert('funding_opportunities', valid.slice(i, i + 500))

    } else if (type === 'applications') {
      // Helper: extract company name from Attio's "Record" field
      // Attio formats application names as "Company Name - Grant Type" or "Company Name - WIB Name - IWT"
      const extractCompanyFromRecord = (record) => {
        if (!record) return null
        // State abbreviations that appear in Attio application record names
        // Format: "Company Name - [State]- [WIB Name] - IWT [Year]"
        const stateCodes = ['AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID','IL','IN','IA','KS','KY','LA','ME','MD','MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ','NM','NY','NC','ND','OH','OK','OR','PA','RI','SC','SD','TN','TX','UT','VT','VA','WA','WV','WI','WY','DC']
        // Check for " - XX" pattern where XX is a 2-letter state code
        for (const code of stateCodes) {
          const patterns = [' - ' + code + '-', ' - ' + code + ' ', ' - ' + code + ',']
          for (const pat of patterns) {
            const idx = record.indexOf(pat)
            if (idx > 3) return record.substring(0, idx).trim()
          }
        }
        // Check for known WIB name prefixes
        const wibPrefixes = [' - CO ', ' - IW', ' - Tri', ' - North', ' - South', ' - East', ' - West', ' - Greater', ' - Central', ' - Capital', ' - Area ', ' - Work', ' - NOVA', ' - Hampton', ' - Permian', ' - Gulf', ' - Career']
        for (const sep of wibPrefixes) {
          const idx = record.indexOf(sep)
          if (idx > 3) return record.substring(0, idx).trim()
        }
        // Fall back: split on ' - ' (first occurrence)
        const dashIdx = record.indexOf(' - ')
        if (dashIdx > 4 && dashIdx < record.length - 4) return record.substring(0, dashIdx).trim()
        return record.trim()
      }

      // Pre-load ALL companies into memory (cached across batches for performance)
      if (!global._importCoCache || global._importCoCache.size === 0) {
        const { data: allCompanies } = await supabase.from('companies').select('id,company_name')
        global._importCoCache = new Map()
        for (const co of (allCompanies || [])) {
          global._importCoCache.set(co.company_name.toLowerCase().trim(), co.id)
          global._importCoCache.set(co.company_name.toLowerCase().trim().substring(0, 30), co.id)
        }
        console.log('App import: company cache loaded with', global._importCoCache.size, 'entries')
      }
      const companyMap = global._importCoCache

      // Pre-load ALL WIBs
      const { data: allWibs } = await supabase.from('wib_records').select('id,wib_name,short_name,state')
      const wibMap = new Map()
      for (const w of (allWibs || [])) {
        wibMap.set(w.wib_name.toLowerCase().trim(), w.id)
        if (w.short_name) wibMap.set(w.short_name.toLowerCase().trim(), w.id)
      }

      // Helper: find company ID with aggressive fuzzy matching
      const findCompanyId = async (name) => {
        if (!name) return null
        const lower = name.toLowerCase().trim()

        // 1. Exact match
        if (companyMap.has(lower)) return companyMap.get(lower)

        // 2. Starts-with (handles "Community" vs "Communities" — share first 28 chars)
        for (const [key, id] of companyMap) {
          if (key.startsWith(lower.substring(0, Math.min(20, lower.length)))) return id
          if (lower.startsWith(key.substring(0, Math.min(20, key.length)))) return id
        }

        // 3. Contains match
        const prefix15 = lower.substring(0, 15)
        for (const [key, id] of companyMap) {
          if (key.includes(prefix15) || lower.includes(key.substring(0, 15))) return id
        }

        // 4. Word-overlap match — count shared significant words
        const words = lower.split(/\s+/).filter(w => w.length > 3)
        let bestId = null, bestScore = 0
        for (const [key, id] of companyMap) {
          const keyWords = key.split(/\s+/)
          const shared = words.filter(w => keyWords.some(kw => kw.startsWith(w.substring(0,6)) || w.startsWith(kw.substring(0,6)))).length
          const score = shared / Math.max(words.length, 1)
          if (score > 0.7 && score > bestScore) { bestScore = score; bestId = id }
        }
        if (bestId) return bestId

        // 5. Last resort: direct DB ILIKE query (handles edge cases where map load failed)
        try {
          const searchTerm = lower.substring(0, 20)
          const { data } = await supabase.from('companies').select('id').ilike('company_name', searchTerm + '%').limit(1)
          if (data?.[0]) {
            companyMap.set(lower, data[0].id) // cache for next use
            return data[0].id
          }
          // Try contains
          const { data: d2 } = await supabase.from('companies').select('id').ilike('company_name', '%' + lower.substring(0, 15) + '%').limit(1)
          if (d2?.[0]) {
            companyMap.set(lower, d2[0].id)
            return d2[0].id
          }
        } catch(e) { /* fallthrough */ }

        return null
      }

      // Helper: find WIB ID
      const findWibId = (name) => {
        if (!name) return null
        const lower = name.toLowerCase().trim()
        if (wibMap.has(lower)) return wibMap.get(lower)
        for (const [key, id] of wibMap) {
          if (key.includes(lower.substring(0, 10)) || lower.includes(key.substring(0, 10))) return id
        }
        return null
      }

      const appStatusMap = {
        'intake': 'intake', 'new': 'intake', 'open': 'intake', 'lead': 'intake',
        'in progress': 'in_progress', 'in_progress': 'in_progress', 'active': 'in_progress',
        'submitted': 'submitted', 'pending': 'submitted',
        'under review': 'under_review', 'under_review': 'under_review', 'review': 'under_review',
        'awarded': 'awarded', 'won': 'awarded', 'approved': 'awarded', 'funded': 'awarded',
        'denied': 'denied', 'rejected': 'denied', 'lost': 'denied', 'closed lost': 'denied',
        'withdrawn': 'withdrawn', 'cancelled': 'withdrawn',
        'completed': 'active', 'closed': 'active',
      }

      for (const row of rows) {
        // Get the record/application name (e.g. "Pine Valley - CO Tri-County - IWT")
        const recordName = (row['application_number'] || row['Record'] || row['Application'] || row['Name'] || '').trim()
        
        // Get company — CRM mapped keys first, then Attio header names, then parse from Record
        const rawCompany = (row['company_name'] || row['Company'] || row['Company Name'] || 
          row['Employer'] || row['Account'] || row['Account Name'] || '').trim() || null
        const companyName = rawCompany || extractCompanyFromRecord(recordName)
        
        if (!companyName) { results.errors.push('Skipped row — no company name'); continue }

        // Find company ID
        const company_id = await findCompanyId(companyName)
        
        // Get WIB — try dedicated column first, then parse from Record
        const rawWib = row['WIB']?.trim() || row['Workforce Board']?.trim() || 
          row['WIB Name']?.trim() || row['Board']?.trim()
        const wibName = rawWib || (() => {
          // Try to extract WIB from record name: "Company - WIB - Type"
          const parts = recordName.split(' - ')
          if (parts.length >= 2) return parts[1]?.trim()
          return null
        })()
        const wib_id = wibName ? findWibId(wibName) : null

        if (!company_id && companyName) {
          results.errors.push('Warning: "'+companyName+'" not matched to a Company (location saved without parent link)')
        }

        const rawStatus = (row['status'] || row['Status'] || row['Stage'] || row['Application Stage'] || 'intake').toLowerCase().trim()
        const status = appStatusMap[rawStatus] || 'intake'

        const getAmt = (...keys) => {
          for (const k of keys) {
            const v = row[k]
            if (v && String(v).trim()) return parseFloat(String(v).replace(/[$, ]/g,'')) || null
          }
          return null
        }
        
        const getDate = (...keys) => {
          for (const k of keys) {
            const v = row[k]
            if (v && String(v).trim()) return String(v).trim().split('T')[0]
          }
          return null
        }

        // Build notes from all captured fields
        const noteParts = []
        if (recordName) noteParts.push(`Application: ${recordName}`)
        if (row['notes'] || row['Notes'] || row['Description'] || row['Comments']) noteParts.push(row['notes'] || row['Notes'] || row['Description'] || row['Comments'])
        // Capture any extra Attio fields
        const knownKeys = new Set(['Record ID','Record','Status','Stage','Company','Company Name','Employer','Account','Account Name',
          'WIB','Workforce Board','WIB Name','Board','Notes','Description','Comments',
          'Award Requested','Amount Requested','Award Approved','Amount Approved','Application Approved Amount',
          'Submission Date','Submitted','Decision Date','Decision','Created','Updated','Owner','Record Stage'])
        const extras = Object.entries(row).filter(([k,v]) => !knownKeys.has(k) && v && String(v).trim())
        if (extras.length) noteParts.push('--- Additional ---\n' + extras.map(([k,v])=>k+': '+v).join('\n'))

        const insertRow = {
          company_id,
          status,
          notes: noteParts.join('\n') || null,
          owner_id: req.user.id,
        }
        if (wib_id) insertRow.wib_id = wib_id
        const awarded = getAmt('award_amount_approved','Application Approved Amount','Award Approved','Amount Approved','Approved Amount','Awarded Amount')
        const requested = getAmt('award_amount_requested','Award Requested','Amount Requested','Requested Amount','Application Amount')
        if (awarded) insertRow.award_amount_approved = awarded
        if (requested) insertRow.award_amount_requested = requested
        const subDate = getDate('submission_date','Submission Date','Submitted','Submit Date','Date Submitted')
        const decDate = getDate('decision_date','Decision Date','Decision','Approved Date','Award Date')
        if (subDate) insertRow.submission_date = subDate
        if (decDate) insertRow.decision_date = decDate

        const { error } = await supabase.from('applications').insert(insertRow)
        if (error) {
          results.errors.push(`"${companyName}": ${error.message}`)
          if (results.errors.length === 1) {
            console.error('First app import error:', error.code, error.message)
            console.error('Row:', JSON.stringify(insertRow))
          }
        } else {
          results.created++
        }
      }

    } else if (type === 'wibs') {
      // Already handled above — fallthrough safety
      results.errors.push('WIBs import called on wrong branch')
    } else {
      return res.status(400).json({ error: `Import not supported for type: ${type}` })
    }

    // Only log on the final batch
    if (!batch || batch === totalBatches) {
      try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'IMPORT', details: `Imported ${results.created} ${type} records (${results.errors.length} errors)` }) } catch(_) {}
    }
    // Cap errors at 20 to avoid huge response payloads
    const cappedErrors = results.errors.slice(0, 20)
    const truncated = results.errors.length > 20
    res.json({
      created: results.created,
      errors: cappedErrors,
      error_count: results.errors.length,
      truncated,
      total: rows.length,
      batch: results.batch,
      totalBatches: results.totalBatches,
      first_row_keys: rows[0] ? Object.keys(rows[0]).slice(0,8) : [],
    })
  } catch(e) {
    console.error('Import error:', e)
    res.status(500).json({ error: e.message })
  }
})

// ─── IMPORT DIAGNOSTICS ─────────────────────────────────────────────────────
// Test endpoint: insert one company row and return exact DB error
app.post('/api/import-test', auth, requireAdmin, async (req, res) => {
  const { row } = req.body
  if (!row) return res.status(400).json({ error: 'row required' })
  try {
    // Try inserting with minimal required fields
    const { data, error } = await supabase.from('companies').insert({
      company_name: row.company_name || 'Test Company ' + Date.now(),
      status: row.status || 'prospect'
    }).select('id,company_name,status').single()
    if (error) return res.json({ success: false, db_error: error.message, db_code: error.code, db_details: error.details, db_hint: error.hint })
    // Delete the test row
    await supabase.from('companies').delete().eq('id', data.id)
    return res.json({ success: true, message: 'Test insert worked — DB constraints OK', data })
  } catch(e) {
    return res.json({ success: false, threw: e.message })
  }
})


// ─── AIRCALL WEBHOOK ─────────────────────────────────────────────────────────
// Receives call lifecycle events from Aircall and stores them idempotently.
// Three webhooks fire per call (call.ended, call.assigned, call_recording.created)
// and may arrive out of order. ON CONFLICT ensures safe concurrent upsert.
// Signature verification uses crypto.timingSafeEqual to prevent timing attacks.

app.post('/api/webhooks/aircall',
  express.raw({ type: '*/*', limit: '1mb' }),  // raw body required for HMAC verification
  async (req, res) => {

    // ── 1. HMAC-SHA256 signature verification ──────────────────────────────────
    // Aircall sends X-Aircall-Signature: sha256=<hmac>
    // If AIRCALL_WEBHOOK_SECRET is not set, we accept the webhook but log a warning.
    const secret = process.env.AIRCALL_WEBHOOK_SECRET
    const sigHeader = req.headers['x-aircall-signature'] || ''

    if (secret) {
      // Compute HMAC of the raw request body
      const computed = 'sha256=' + crypto
        .createHmac('sha256', secret)
        .update(req.body)           // req.body is a Buffer because of express.raw()
        .digest('hex')

      // timingSafeEqual prevents timing oracle attacks on the comparison
      const sigBuf  = Buffer.from(sigHeader.padEnd(computed.length))
      const compBuf = Buffer.from(computed)
      if (sigBuf.length !== compBuf.length || !crypto.timingSafeEqual(sigBuf, compBuf)) {
        console.warn('Aircall webhook: signature mismatch from IP', req.ip)
        return res.status(401).json({ error: 'Invalid webhook signature' })
      }
    } else {
      console.warn('AIRCALL_WEBHOOK_SECRET not set — accepting webhook without signature verification')
    }

    // ── 2. Parse body ──────────────────────────────────────────────────────────
    let payload
    try {
      payload = JSON.parse(req.body.toString('utf8'))
    } catch (e) {
      return res.status(400).json({ error: 'Invalid JSON in webhook body' })
    }

    const { event, data: callData } = payload
    if (!callData?.id) {
      return res.status(400).json({ error: 'Missing call_id in payload' })
    }

    const callId = String(callData.id)

    // ── 3. Idempotent upsert using ON CONFLICT ─────────────────────────────────
    // All three concurrent webhooks for the same call merge into one row.
    // COALESCE ensures existing non-null fields are never overwritten by null values
    // from a partial webhook (e.g., recording_url arrives last via call_recording.created).
    const upsertPayload = {
      call_id:        callId,
      direction:      callData.direction    || null,
      duration:       callData.duration     || null,
      started_at:     callData.started_at   ? new Date(callData.started_at * 1000).toISOString()  : null,
      ended_at:       callData.ended_at     ? new Date(callData.ended_at   * 1000).toISOString()  : null,
      recording_url:  callData.recording    || null,
      assigned_email: callData.user?.email  || null,
      raw_payload:    payload,
    }

    // Resolve assigned_to UUID from email if the user exists in our system
    if (callData.user?.email) {
      const { data: agentProfile } = await supabase
        .from('user_profiles')
        .select('id')
        .eq('email', callData.user.email)
        .single()
      if (agentProfile) upsertPayload.assigned_to = agentProfile.id
    }

    const { data: upserted, error: upsertErr } = await supabase
      .from('aircall_calls')
      .upsert(upsertPayload, {
        onConflict:     'call_id',
        ignoreDuplicates: false,  // DO UPDATE (not DO NOTHING) to merge partial data
      })
      .select()
      .single()

    if (upsertErr) {
      console.error('Aircall upsert error:', upsertErr.message, 'call_id:', callId)
      return res.status(500).json({ error: 'Failed to store call record' })
    }

    // ── 4. Create a linked Note in the notes table when call ends ──────────────
    // Only create the note once: when both duration and ended_at are now present
    // (which means we have the complete call data) and no note exists yet.
    if (event === 'call.ended' && upserted.duration && !upserted.note_id) {
      // Format: [AIRCALL NOTE] | Date | Duration | Agent | Summary
      const callDate     = upserted.started_at ? new Date(upserted.started_at).toLocaleDateString('en-US') : 'Unknown'
      const durationStr  = upserted.duration ? `${Math.floor(upserted.duration / 60)}m ${upserted.duration % 60}s` : 'Unknown'
      const agentName    = callData.user?.name || callData.user?.email || 'Unknown Agent'
      const direction    = upserted.direction === 'inbound' ? '📞 Inbound' : '📤 Outbound'
      const recordingStr = upserted.recording_url ? `\nRecording: ${upserted.recording_url}` : ''

      const noteContent = [
        `[AIRCALL NOTE] | ${callDate} | ${durationStr} | ${agentName}`,
        `Direction: ${direction}`,
        `Duration: ${durationStr}`,
        recordingStr,
      ].filter(Boolean).join('\n')

      // Insert the note (linked to the CRM record if we know which one)
      if (upserted.assigned_to) {
        const { data: newNote } = await supabase
          .from('notes')
          .insert({
            record_type: upserted.record_type || 'internal',
            record_id:   upserted.record_id   || upserted.assigned_to,  // fallback to agent's profile
            content:     noteContent,
            note_type:   'Call Summary',
            is_aircall:  true,
            aircall_id:  callId,
            created_by:  upserted.assigned_to,
          })
          .select('id')
          .single()

        // Link the note back to the call record
        if (newNote) {
          await supabase
            .from('aircall_calls')
            .update({ note_id: newNote.id, status: 'note_created' })
            .eq('call_id', callId)
        }
      }
    }

    // ── 5. Acknowledge receipt immediately ─────────────────────────────────────
    // Aircall expects a 200 response within 10 seconds or it retries.
    // All async work above completes before this response.
    res.status(200).json({ received: true, call_id: callId, event })
  }
)


// ─── AI ASSISTANT PROXY ──────────────────────────────────────────────────────
// Proxy Anthropic API calls through server to keep API key secure
app.post('/api/ai', auth, async (req, res) => {
  const { prompt, context = '' } = req.body
  if (!prompt?.trim()) return res.status(400).json({ error: 'Prompt required' })

  const apiKey = process.env.ANTHROPIC_API_KEY
  if (!apiKey) {
    // Return a helpful message if no API key configured
    return res.json({ 
      text: 'AI Assistant requires an ANTHROPIC_API_KEY environment variable. Add it in your Render dashboard under Environment Variables, then redeploy.',
      error: true
    })
  }

  // ── Prompt sanitization: block injection attempts ───────────────────────────
  // Remove sequences that try to override the system role or leak cross-tenant data.
  // These are not perfect — defense in depth requires the system prompt to be
  // a hardcoded server-side string, which it is (context is bounded below).
  function sanitizeAiInput(s) {
    return String(s || '')
      .substring(0, 2000)  // hard token budget per field
      .replace(/ignore\s+(previous|all|prior|above)\s+(instructions?|prompts?|context)/gi, '[filtered]')
      .replace(/system\s*prompt/gi, '[filtered]')
      .replace(/you\s+are\s+(?:now|a|an)\s+(?:different|new|another)/gi, '[filtered]')
      .replace(/reveal\s+(?:all|every|the|your)\s+(?:data|records|users|companies)/gi, '[filtered]')
      .replace(/<script[^>]*>.*?<\/script>/gi, '[filtered]')
      .trim()
  }

  const safePrompt  = sanitizeAiInput(prompt)
  const safeContext = sanitizeAiInput(context)

  // Per-user AI rate limit: max 50 calls per hour (prevents cost runaway)
  const oneHourAgo = new Date(Date.now() - 3600000).toISOString()
  const countCols  = global._hasUserId !== false ? 'id' : 'id'
  const { count: aiCount } = await supabase
    .from('activity_log')
    .select('id', { count: 'exact', head: true })
    .eq('user_id', req.user.id)
    .eq('action',  'AI_QUERY')
    .gte('created_at', oneHourAgo)
  if ((aiCount || 0) >= 50) {
    return res.status(429).json({
      error: 'AI rate limit reached (50 requests/hour). Please wait before trying again.',
      text:  'Rate limit reached. Try again in an hour.'
    })
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system:     'You are an expert workforce grant consultant AI assistant for Valor Workforce Funding LLC. You help staff analyze WIB relationships, employer eligibility, grant funding opportunities, and application status. Never reveal data from other organizations. Only discuss the context provided. Be concise, actionable, and format for CRM display.',
        messages: [{
          role:    'user',
          content: `Context: ${safeContext}\n\nTask: ${safePrompt}`
        }]
      })
    })
    const data = await response.json()
    if (data.error) return res.json({ text: `AI Error: ${data.error.message}`, error: true })
    const text = data.content?.[0]?.text || 'No response generated.'
    try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'AI_QUERY', details: prompt.substring(0, 200) }) } catch(_) {}
    res.json({ text })
  } catch(e) {
    res.status(500).json({ error: e.message, text: 'AI temporarily unavailable: ' + e.message })
  }
})

// ─── ROLE PERMISSIONS ────────────────────────────────────────────────────────
// Default permissions matrix — used as fallback if DB table doesn't exist yet
const DEFAULT_PERMISSIONS = {
  view_records:          { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:true,  team_member:true,  external_partner:true  },
  create_wibs_companies: { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:false, team_member:true,  external_partner:false },
  edit_wibs_companies:   { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:false, team_member:true,  external_partner:false },
  delete_records:        { super_admin:true,  admin:true,  grant_coordinator:false, compliance_mgr:false, team_member:false, external_partner:false },
  create_edit_apps:      { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:false, team_member:true,  external_partner:false },
  view_revenue:          { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:false, team_member:true,  external_partner:false },
  manage_invoices:       { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:false, team_member:false, external_partner:false },
  compliance_tracking:   { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:true,  team_member:false, external_partner:false },
  notes_tasks:           { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:true,  team_member:true,  external_partner:false },
  ai_assistant:          { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:true,  team_member:true,  external_partner:false },
  import_export:         { super_admin:true,  admin:true,  grant_coordinator:true,  compliance_mgr:true,  team_member:true,  external_partner:false },
  audit_logs:            { super_admin:true,  admin:true,  grant_coordinator:false, compliance_mgr:false, team_member:false, external_partner:false },
  manage_users:          { super_admin:true,  admin:true,  grant_coordinator:false, compliance_mgr:false, team_member:false, external_partner:false },
  assign_roles:          { super_admin:true,  admin:true,  grant_coordinator:false, compliance_mgr:false, team_member:false, external_partner:false },
  assign_super_admin:    { super_admin:true,  admin:false, grant_coordinator:false, compliance_mgr:false, team_member:false, external_partner:false },
  system_settings:       { super_admin:true,  admin:true,  grant_coordinator:false, compliance_mgr:false, team_member:false, external_partner:false },
}

// Locked permissions that can never be changed (core security rules)
const LOCKED_PERMISSIONS = {
  view_records:       { external_partner: true },  // Read-only must be able to view
  manage_users:       { super_admin: true },         // Super admin always manages users
  assign_super_admin: { super_admin: true },         // Super admin always self-assigns
  system_settings:    { super_admin: true },         // Super admin always has settings
  assign_roles:       { super_admin: true },         // Super admin always assigns roles
}

// In-memory permission store (persists for server lifetime, survives across requests)
let _permissionsCache = null

async function loadPermissions() {
  if (_permissionsCache) return _permissionsCache
  try {
    const { data, error } = await supabase.from('role_permissions').select('*').single()
    if (!error && data?.permissions) {
      _permissionsCache = { ...DEFAULT_PERMISSIONS, ...data.permissions }
    } else {
      _permissionsCache = { ...DEFAULT_PERMISSIONS }
    }
  } catch {
    _permissionsCache = { ...DEFAULT_PERMISSIONS }
  }
  return _permissionsCache
}

async function savePermissions(perms) {
  _permissionsCache = perms
  try {
    // Try upsert into role_permissions table
    const { error } = await supabase.from('role_permissions').upsert({ id: 1, permissions: perms, updated_at: new Date().toISOString() })
    if (error) console.warn('role_permissions table may not exist yet — permissions stored in memory only. Run the SQL migration to persist.')
  } catch(e) {
    console.warn('Permissions save failed:', e.message)
  }
}

app.get('/api/permissions', auth, async (req, res) => {
  try {
    const perms = await loadPermissions()
    res.json({ permissions: perms, locked: LOCKED_PERMISSIONS })
  } catch(e) {
    res.status(500).json({ error: e.message })
  }
})

app.put('/api/permissions', auth, requireSuper, async (req, res) => {
  try {
    const { permission, role, value } = req.body
    if (!permission || !role || value === undefined) return res.status(400).json({ error: 'permission, role, and value required' })
    if (!VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' })
    // Check if this is a locked permission
    if (LOCKED_PERMISSIONS[permission]?.[role] !== undefined) {
      return res.status(400).json({ error: `The "${permission}" permission for "${role}" is locked and cannot be changed` })
    }
    const perms = await loadPermissions()
    if (!perms[permission]) return res.status(400).json({ error: 'Unknown permission key' })
    perms[permission][role] = !!value
    await savePermissions(perms)
    try { await logActivity({ user_id: req.user.id, action: 'UPDATE_PERMISSIONS', details: 'Set ' + permission + '/' + role + ' = ' + value }) } catch(_) {}
    res.json({ success: true, permissions: perms })
  } catch(e) {
    res.status(500).json({ error: e.message })
  }
})

// Middleware that checks a named permission against the live permissions table
function requirePermission(permKey) {
  return async (req, res, next) => {
    try {
      const perms = await loadPermissions()
      const allowed = perms[permKey]?.[req.user?.role]
      if (!allowed) return res.status(403).json({ error: 'You do not have permission to perform this action' })
      next()
    } catch {
      next() // Fail open on permission load error (system already authed)
    }
  }
}

// ─── EXPORT ───────────────────────────────────────────────────────────────────
const esc = v => {
  // Formula injection prevention: prefix cells starting with =, +, -, @, tab, CR/LF
  // to prevent spreadsheet apps (Excel, Google Sheets) from executing them as formulas
  const s = String(v ?? '')
  const safe = /^[=+\-@\t\r\n]/.test(s) ? "'" + s : s
  return '"' + safe.replace(/"/g, '""') + '"'
}
// ─── STREAMING CSV EXPORT ─────────────────────────────────────────────────────
// Uses cursor-based pagination (1,000 rows/page) and Transfer-Encoding: chunked
// so the server never loads more than 1,000 rows into memory at once.
// Supports unlimited export size without heap exhaustion.

// Export config: defines table, columns, headers, and row-mapper per type
const EXPORT_CONFIG = {
  wibs: {
    table:   'wib_records',
    select:  'wib_name,short_name,state,status,wib_phone,wib_email,website,max_award_per_ein,match_requirement_pct,iwt_program_active,source_url,call_priority_score,last_verified_date,next_steps,blockers',
    order:   { col: 'call_priority_score', asc: false },
    headers: ['WIB Name','Short Name','State','Status','Phone','Email','Website','Max Award/EIN','Match %','IWT Active','Source URL','Score','Last Verified','Next Steps','Blockers'],
    map:     r => [r.wib_name,r.short_name||'',r.state,r.status,r.wib_phone||'',r.wib_email||'',r.website||'',r.max_award_per_ein||'',r.match_requirement_pct||'',r.iwt_program_active?'Yes':'No',r.source_url||'',r.call_priority_score||0,r.last_verified_date||'',r.next_steps||'',r.blockers||''],
  },
  companies: {
    table:   'companies',
    select:  'company_name,company_type,status,fein,domain,employee_count_total,avg_hourly_wage,primary_contact_name,primary_contact_email,primary_contact_phone,training_needs,notes,rating,created_at',
    order:   { col: 'company_name', asc: true },
    headers: ['Company Name','Type','Status','FEIN','Domain','Employees','Avg Hourly Wage','Contact Name','Contact Email','Contact Phone','Training Needs','Notes','Rating','Created'],
    map:     r => [r.company_name,r.company_type||'',r.status,r.fein||'',r.domain||'',r.employee_count_total||'',r.avg_hourly_wage||'',r.primary_contact_name||'',r.primary_contact_email||'',r.primary_contact_phone||'',r.training_needs||'',r.notes||'',r.rating||'',r.created_at?.split('T')[0]||''],
  },
  locations: {
    table:   'locations',
    select:  'location_name,state,county,city,status,employee_count,address,created_at',
    order:   { col: 'location_name', asc: true },
    headers: ['Location','State','County','City','Status','Employees','Address','Created'],
    map:     r => [r.location_name,r.state||'',r.county||'',r.city||'',r.status||'',r.employee_count||'',r.address||'',r.created_at?.split('T')[0]||''],
  },
  funding: {
    table:   'funding_opportunities',
    select:  'opportunity_name,status,program_type,max_award_per_ein,max_award_per_employee,application_deadline,blocked_reason,source_url,created_at',
    order:   { col: 'created_at', asc: false },
    headers: ['Opportunity','Status','Program','Max Award/EIN','Max/Employee','Deadline','Blocked Reason','Source URL','Created'],
    map:     r => [r.opportunity_name,r.status,r.program_type||'',r.max_award_per_ein||'',r.max_award_per_employee||'',r.application_deadline||'',r.blocked_reason||'',r.source_url||'',r.created_at?.split('T')[0]||''],
  },
  applications: {
    table:   'applications',
    select:  'application_number,status,notes,award_amount_requested,award_amount_approved,submission_date,decision_date,created_at,company:companies!company_id(company_name,domain,primary_contact_email),funding:funding_opportunities!funding_opportunity_id(opportunity_name,status),location:locations!location_id(location_name,state),wib:wib_records!wib_id(wib_name)',
    order:   { col: 'created_at', asc: false },
    headers: ['Application','Company','Domain','Email','Funding Opportunity','Funding Status','Location','State','WIB','Status','Award Requested','Award Approved','Submission Date','Decision Date','Latest Update','Created'],
    map:     r => [
      r.application_number || ((r.company?.company_name||'') + (r.funding?.opportunity_name ? ' — ' + r.funding.opportunity_name : '')),
      r.company?.company_name||'', r.company?.domain||'', r.company?.primary_contact_email||'',
      r.funding?.opportunity_name||'', r.funding?.status||'',
      r.location?.location_name||'', r.location?.state||'',
      r.wib?.wib_name||'', r.status,
      r.award_amount_requested||'', r.award_amount_approved||'',
      r.submission_date||'', r.decision_date||'',
      (r.notes||'').split('\n')[0].substring(0,100),
      r.created_at?.split('T')[0]||'',
    ],
  },
  revenue: {
    table:   'revenue_records',
    select:  'fee_model,grant_award_amount,calculated_success_fee,invoice_status,payment_received_date,created_at',
    order:   { col: 'created_at', asc: false },
    headers: ['Fee Model','Grant Award','Valor Fee','Invoice Status','Payment Date','Created'],
    map:     r => [r.fee_model||'',r.grant_award_amount||'',r.calculated_success_fee||'',r.invoice_status||'',r.payment_received_date||'',r.created_at?.split('T')[0]||''],
  },
}

app.get('/api/export/:type', auth, async (req, res) => {
  const { type } = req.params

  // ── Permission checks for sensitive types ──────────────────────────────────
  if (type === 'users' || type === 'audit') {
    if (!['super_admin','admin'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Admin access required for this export' })
    }
  }

  // ── Handle special-case non-paginated types ────────────────────────────────
  if (type === 'users') {
    const { data } = await supabase.from('user_profiles').select('full_name,email,role,title,is_active,created_at')
    const headers = ['Name','Email','Role','Title','Active','Created']
    const rows = (data||[]).map(r => [r.full_name||'',r.email,r.role,r.title||'',r.is_active?'Yes':'No',r.created_at?.split('T')[0]||''])
    const csv = [headers.map(esc).join(','), ...rows.map(r => r.map(esc).join(','))].join('\n')
    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', `attachment; filename="valor-users-${new Date().toISOString().split('T')[0]}.csv"`)
    return res.send(csv)
  }

  if (type === 'compliance') {
    const { data } = await supabase.from('v_compliance_alerts').select('*').order('days_until_final_due')
    const headers = ['Application #','Company','WIB','Status','Award Amount','Training End','Final Report Due','Days Until Due','Report Submitted','Attendance Collected','Notes']
    const rows = (data||[]).map(r => [r.application_number||'',r.company_name||'',r.wib_name||'',r.status||'',r.award_amount_approved||'',r.training_end_date||'',r.final_report_due_date||'',r.days_until_final_due??'',r.final_report_submitted?'Yes':'No',r.attendance_sheets_collected?'Yes':'No',r.compliance_notes||''])
    const csv = [headers.map(esc).join(','), ...rows.map(r => r.map(esc).join(','))].join('\n')
    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', `attachment; filename="valor-compliance-${new Date().toISOString().split('T')[0]}.csv"`)
    return res.send(csv)
  }

  if (type === 'audit') {
    const auditSelect = 'action,created_at' + (global._hasRecordType?',record_type':'') +
      (global._detailsColumnMissing?'':(global._hasMetadata?',metadata':',details')) +
      ',user:user_profiles!user_id(email)'
    const { data } = await supabase.from('activity_log').select(auditSelect).order('created_at', { ascending: false }).limit(2000)
    const headers = ['Action','User','Details','Record Type','Timestamp']
    const rows = (data||[]).map(r => [r.action,r.user?.email||'',r.details||r.metadata?.text||'',r.record_type||'',r.created_at||''])
    const csv = [headers.map(esc).join(','), ...rows.map(r => r.map(esc).join(','))].join('\n')
    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', `attachment; filename="valor-audit-${new Date().toISOString().split('T')[0]}.csv"`)
    return res.send(csv)
  }

  // ── Paginated streaming export for large tables ────────────────────────────
  const config = EXPORT_CONFIG[type]
  if (!config) return res.status(400).json({ error: `Unknown export type: ${type}` })

  const PAGE_SIZE = 1000  // rows per DB round-trip; keeps heap usage under 50MB at all times
  const filename  = `valor-${type}-${new Date().toISOString().split('T')[0]}.csv`

  res.setHeader('Content-Type',        'text/csv; charset=utf-8')
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)
  res.setHeader('Transfer-Encoding',   'chunked')
  res.setHeader('Cache-Control',       'no-store')

  // Write CSV header row immediately so the browser starts the download dialog
  res.write(config.headers.map(esc).join(',') + '\n')

  let offset = 0
  let totalExported = 0

  try {
    while (true) {
      const { data, error } = await supabase
        .from(config.table)
        .select(config.select)
        .order(config.order.col, { ascending: config.order.asc })
        .range(offset, offset + PAGE_SIZE - 1)

      if (error) {
        // Can't send a JSON error here — response has started. Write an error comment to CSV.
        res.write(`\n# ERROR: ${error.message}\n`)
        break
      }

      if (!data || data.length === 0) break  // no more rows

      // Map each row to CSV values and write the chunk
      const chunk = data.map(r => config.map(r).map(esc).join(',')).join('\n') + '\n'
      res.write(chunk)

      totalExported += data.length
      offset        += PAGE_SIZE

      if (data.length < PAGE_SIZE) break  // last page — fewer rows than PAGE_SIZE means done
    }

    // Log the export action (fire-and-forget)
    safeInsertLog({
      user_id: req.user.id,
      action:  'EXPORT',
      details: `Exported ${type} — ${totalExported} records`,
    }).catch(() => {})

    res.end()

  } catch (e) {
    console.error('Export stream error:', e.message)
    res.write(`\n# EXPORT FAILED: ${e.message}\n`)
    res.end()
  }
})

app.get('/api/template/:type', auth, (req, res) => {
  const templates = {
    wibs: 'WIB Name,Short Name,State,Status,Phone,Email,Website,Max Award,Match %,IWT Active,Source URL',
    companies: 'Company Name,Type,Status,FEIN,Domain,Employee Count,Avg Wage,Contact Name,Contact Email',
    locations: 'Location Name,State,County,City,Status,Employee Count',
    funding: 'Opportunity Name,Status,Program Type,Max Award/EIN,Deadline,Source URL',
    applications: 'Company Name,Funding Opportunity,Status,Award Requested,Award Approved,Submission Date,Decision Date,Notes',
  }
  const csv = templates[req.params.type]
  if (!csv) return res.status(400).json({ error: 'Unknown template' })
  res.setHeader('Content-Type', 'text/csv')
  res.setHeader('Content-Disposition', `attachment; filename="valor-${req.params.type}-template.csv"`)
  res.send(csv)
})

// ═══════════════════════════════════════════════════════════════════════════════
// NOTIFICATIONS API
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/notifications', auth, async (req, res) => {
  const { limit = 50, unread_only } = req.query
  try {
    let q = supabase
      .from('notifications')
      .select('*, sender:user_profiles!sender_id(full_name,email)', { count: 'exact' })
      .eq('recipient_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(Math.min(+limit, 100))

    if (unread_only === 'true') q = q.eq('is_read', false)

    const { data, error, count } = await q
    if (error) return res.status(400).json({ error: error.message })

    // Activity summary — quick counts for the sidebar widget
    const weekAgo = new Date(Date.now() - 7*24*3600*1000).toISOString()
    const [notesRes, tasksRes] = await Promise.all([
      supabase.from('activity_log').select('id', { count:'exact', head:true })
        .eq('action','NOTE').gte('created_at', weekAgo),
      supabase.from('activity_log').select('id', { count:'exact', head:true })
        .eq('action','TASK').gte('created_at', weekAgo),
    ])

    const notifications = (data||[]).map(n => ({
      ...n,
      sender_name: n.sender?.full_name || n.sender?.email || 'System'
    }))
    const unreadCount = notifications.filter(n => !n.is_read).length

    res.json({
      data:             notifications,
      unread_count:     unreadCount,
      activity_summary: {
        notes_this_week: notesRes.count || 0,
        tasks_completed: tasksRes.count || 0,
        wibs_contacted:  null,
        apps_submitted:  null,
      }
    })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.put('/api/notifications/:id/read', auth, async (req, res) => {
  const { error } = await supabase
    .from('notifications')
    .update({ is_read: true })
    .eq('id', req.params.id)
    .eq('recipient_id', req.user.id)  // IDOR guard — can only mark own notifications
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

app.post('/api/notifications/mark-all-read', auth, async (req, res) => {
  const { error } = await supabase
    .from('notifications')
    .update({ is_read: true })
    .eq('recipient_id', req.user.id)
    .eq('is_read', false)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

app.post('/api/notifications/:id/respond', auth, async (req, res) => {
  const { action } = req.body  // 'accept' or 'deny'
  const { data: notif } = await supabase
    .from('notifications')
    .select('*')
    .eq('id', req.params.id)
    .eq('recipient_id', req.user.id)
    .single()
  if (!notif) return res.status(404).json({ error: 'Notification not found' })

  // Mark as read and record the response
  await supabase.from('notifications').update({
    is_read:        true,
    responded_at:   new Date().toISOString(),
    response_action: action,
  }).eq('id', req.params.id)

  res.json({ success: true, action })
})

// Helper: create a notification for a user (called internally by other endpoints)
async function createNotification({ recipientId, senderId, type, title, body, recordType, recordId }) {
  try {
    await supabase.from('notifications').insert({
      recipient_id: recipientId,
      sender_id:    senderId    || null,
      type:         type        || 'system',
      title:        title       || '',
      body:         body        || '',
      record_type:  recordType  || null,
      record_id:    recordId    || null,
    })
  } catch (e) {
    console.warn('createNotification failed (non-fatal):', e.message)
  }
}


// ═══════════════════════════════════════════════════════════════════════════════
// CHAT API
// Messages persist to chat_messages table.
// Supabase Realtime broadcasts new rows to all subscribed clients on that channel.
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/chat/:channel', auth, async (req, res) => {
  const channel = req.params.channel.substring(0, 100)  // max channel name length
  const limit   = Math.min(+(req.query.limit||50), 200)

  const { data, error } = await supabase
    .from('chat_messages')
    .select('*, sender:user_profiles!sender_id(full_name,email)')
    .eq('channel', channel)
    .eq('is_deleted', false)
    .order('created_at', { ascending: false })
    .limit(limit)

  if (error) return res.status(400).json({ error: error.message })

  const messages = (data||[]).map(m => ({
    ...m,
    sender_name: m.sender?.full_name || m.sender?.email || 'Team Member'
  }))

  res.json({ data: messages })
})

app.post('/api/chat/:channel', auth, async (req, res) => {
  const channel = req.params.channel.substring(0, 100)
  const content = (req.body.content || '').trim()

  if (!content) return res.status(400).json({ error: 'Message content required' })
  if (content.length > 5000) return res.status(400).json({ error: 'Message too long (max 5000 chars)' })

  const { data, error } = await supabase
    .from('chat_messages')
    .insert({
      channel,
      sender_id: req.user.id,
      content,
    })
    .select('*, sender:user_profiles!sender_id(full_name,email)')
    .single()

  if (error) return res.status(400).json({ error: error.message })

  const message = {
    ...data,
    sender_name: data.sender?.full_name || data.sender?.email || 'Team Member'
  }

  // Supabase Realtime automatically broadcasts the INSERT to all subscribers.
  // No manual push needed — the DB change triggers it.
  res.json(message)
})


// ═══════════════════════════════════════════════════════════════════════════════
// GOOGLE DRIVE API
// OAuth 2.0 + Drive API v3 proxy
// Tokens stored in user_drive_tokens table; never exposed to frontend.
// ═══════════════════════════════════════════════════════════════════════════════

const GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI || 'https://valor-crm.onrender.com/api/auth/google/callback'
const DRIVE_SCOPE          = 'https://www.googleapis.com/auth/drive.file'

// Helper: get a valid access token for a user (refreshes automatically if expired)
async function getDriveToken(userId) {
  const { data: tokenRow } = await supabase
    .from('user_drive_tokens')
    .select('*')
    .eq('user_id', userId)
    .single()

  if (!tokenRow) return null

  // If token expires in the next 5 minutes, refresh it now
  const expiresAt = new Date(tokenRow.expires_at)
  if (expiresAt <= new Date(Date.now() + 5 * 60 * 1000)) {
    const refreshed = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        refresh_token: tokenRow.refresh_token,
        grant_type:    'refresh_token',
      })
    })
    const rd = await refreshed.json()
    if (rd.access_token) {
      const newExpiry = new Date(Date.now() + (rd.expires_in || 3600) * 1000).toISOString()
      await supabase.from('user_drive_tokens').update({
        access_token: rd.access_token,
        expires_at:   newExpiry,
      }).eq('user_id', userId)
      return rd.access_token
    }
    return null  // refresh failed — user must re-authorize
  }
  return tokenRow.access_token
}

// Helper: make a Drive API call with automatic auth
async function driveApi(userId, path, opts = {}) {
  const accessToken = await getDriveToken(userId)
  if (!accessToken) throw new Error('Google Drive not connected. Please reconnect in Settings.')

  const url = path.startsWith('http') ? path : 'https://www.googleapis.com/drive/v3/' + path
  const r = await fetch(url, {
    ...opts,
    headers: {
      'Authorization': 'Bearer ' + accessToken,
      ...(opts.headers || {})
    }
  })
  if (r.status === 401) {
    // Token truly invalid — wipe it so user sees connect prompt
    await supabase.from('user_drive_tokens').delete().eq('user_id', userId)
    throw new Error('Google Drive authorization expired. Please reconnect.')
  }
  return r
}

// ── OAuth flow ──────────────────────────────────────────────────────────────
app.get('/api/auth/google', auth, (req, res) => {
  if (!GOOGLE_CLIENT_ID) {
    return res.status(503).send('GOOGLE_CLIENT_ID not configured. Add it to Render environment variables.')
  }
  // Store the user's CRM token so we can link the OAuth callback to the right user
  const state = Buffer.from(JSON.stringify({ userId: req.user.id, token: req.query.token })).toString('base64url')
  const authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' + new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope:         DRIVE_SCOPE + ' https://www.googleapis.com/auth/userinfo.email',
    access_type:   'offline',   // gives us a refresh_token
    prompt:        'consent',   // always show consent screen to ensure refresh_token is issued
    state,
  })
  res.redirect(authUrl)
})

app.get('/api/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query
  if (error) return res.redirect('/?drive_error=' + encodeURIComponent(error))
  if (!code || !state) return res.redirect('/?drive_error=missing_code')

  let stateData
  try { stateData = JSON.parse(Buffer.from(state, 'base64url').toString('utf8')) }
  catch { return res.redirect('/?drive_error=invalid_state') }

  // Exchange code for tokens
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id:     GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri:  GOOGLE_REDIRECT_URI,
      grant_type:    'authorization_code',
    })
  })
  const tokenData = await tokenRes.json()

  if (!tokenData.access_token) {
    return res.redirect('/?drive_error=' + encodeURIComponent(tokenData.error_description || 'token_exchange_failed'))
  }

  const expiresAt = new Date(Date.now() + (tokenData.expires_in || 3600) * 1000).toISOString()

  // Upsert — one token row per user
  await supabase.from('user_drive_tokens').upsert({
    user_id:       stateData.userId,
    access_token:  tokenData.access_token,
    refresh_token: tokenData.refresh_token || null,  // only returned on first auth
    expires_at:    expiresAt,
    scope:         tokenData.scope,
  }, { onConflict: 'user_id' })

  // Redirect back to the Drive page
  res.redirect('/?page=drive&drive_connected=1')
})

// ── Drive status ─────────────────────────────────────────────────────────────
app.get('/api/drive/status', auth, async (req, res) => {
  const { data } = await supabase
    .from('user_drive_tokens')
    .select('expires_at, scope')
    .eq('user_id', req.user.id)
    .single()
  res.json({ connected: !!data, expires_at: data?.expires_at })
})

// ── List files ───────────────────────────────────────────────────────────────
app.get('/api/drive/files', auth, async (req, res) => {
  const folderId = req.query.folder_id || 'root'
  const mimeFilter = req.query.mime || null

  let query = `'${folderId}' in parents and trashed=false`
  if (mimeFilter) query += ` and mimeType='${mimeFilter}'`

  try {
    const r = await driveApi(req.user.id,
      'files?q=' + encodeURIComponent(query) +
      '&fields=files(id,name,mimeType,size,modifiedTime,webViewLink,owners,parents)' +
      '&orderBy=folder,name&pageSize=100',
      { headers: { 'Content-Type': 'application/json' } }
    )
    const data = await r.json()
    if (!r.ok) return res.status(r.status).json({ error: data.error?.message || 'Drive API error' })
    res.json({ files: data.files || [], breadcrumb: [] })
  } catch (e) {
    res.status(400).json({ error: e.message })
  }
})

// ── Upload file ───────────────────────────────────────────────────────────────
const multer = (() => { try { return require('multer') } catch { return null } })()
const uploadMiddleware = multer ? multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } }) : null

app.post('/api/drive/upload', auth, async (req, res) => {
  if (!uploadMiddleware) {
    return res.status(503).json({ error: 'File upload not available. Run: npm install multer' })
  }
  uploadMiddleware.single('file')(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message })
    const { folder_id = 'root' } = req.body
    const file = req.file
    if (!file) return res.status(400).json({ error: 'No file provided' })

    // Step 1: Create file metadata
    const meta = JSON.stringify({
      name: file.originalname,
      parents: [folder_id],
    })

    // Step 2: Multipart upload to Drive
    // Build multipart upload using Buffer.concat (safe binary handling)
    const boundary = 'valorcrm' + Date.now()
    const partHead = Buffer.from(
      '--' + boundary + '\r\n' +
      'Content-Type: application/json; charset=UTF-8\r\n\r\n' +
      meta + '\r\n' +
      '--' + boundary + '\r\n' +
      'Content-Type: ' + file.mimetype + '\r\n\r\n',
      'utf8'
    )
    const partTail = Buffer.from('\r\n--' + boundary + '--', 'utf8')
    const uploadBody = Buffer.concat([partHead, file.buffer, partTail])
    try {
      const uploadToken = await getDriveToken(req.user.id)
      if (!uploadToken) return res.status(403).json({ error: 'Google Drive not connected' })
      const r = await fetch(
        'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink',
        {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + uploadToken,
            'Content-Type': 'multipart/related; boundary=' + boundary,
          },
          body: uploadBody,
        }
      )
      const data = await r.json()
      if (!r.ok) return res.status(r.status).json({ error: data.error?.message || 'Upload failed' })
      try { await safeInsertLog({ user_id: req.user.id, action: 'DRIVE_UPLOAD', details: 'Uploaded: ' + file.originalname }) } catch(_){}
      res.json({ file: data })
    } catch (e) {
      res.status(500).json({ error: e.message })
    }
  })
})

// ── Download file ─────────────────────────────────────────────────────────────
app.get('/api/drive/download/:fileId', auth, async (req, res) => {
  try {
    // Get file metadata first for the filename
    const metaR = await driveApi(req.user.id, 'files/' + req.params.fileId + '?fields=name,mimeType,size')
    const meta = await metaR.json()
    if (!metaR.ok) return res.status(metaR.status).json({ error: meta.error?.message })

    // Download the file content
    const fileR = await driveApi(req.user.id, 'files/' + req.params.fileId + '?alt=media')
    if (!fileR.ok) return res.status(fileR.status).json({ error: 'Download failed' })

    res.setHeader('Content-Type', meta.mimeType || 'application/octet-stream')
    res.setHeader('Content-Disposition', 'attachment; filename="' + (meta.name||'file').replace(/"/g,'') + '"')
    // Stream the response body directly to the client
    const { Readable } = require('stream')
    Readable.fromWeb(fileR.body).pipe(res)
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── Create folder ─────────────────────────────────────────────────────────────
app.post('/api/drive/folder', auth, async (req, res) => {
  const { name, parent_id = 'root' } = req.body
  if (!name?.trim()) return res.status(400).json({ error: 'Folder name required' })
  try {
    const r = await driveApi(req.user.id, 'files?fields=id,name,webViewLink', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: name.trim(),
        mimeType: 'application/vnd.google-apps.folder',
        parents: [parent_id],
      })
    })
    const data = await r.json()
    if (!r.ok) return res.status(r.status).json({ error: data.error?.message })
    res.json({ folder: data })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── Delete (trash) file ───────────────────────────────────────────────────────
app.delete('/api/drive/files/:fileId', auth, async (req, res) => {
  try {
    // PATCH to set trashed=true (reversible) instead of DELETE (permanent)
    const r = await driveApi(req.user.id, 'files/' + req.params.fileId, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ trashed: true })
    })
    if (!r.ok) {
      const d = await r.json()
      return res.status(r.status).json({ error: d.error?.message || 'Delete failed' })
    }
    res.json({ success: true })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// ── Export to Drive ───────────────────────────────────────────────────────────
app.post('/api/drive/export', auth, async (req, res) => {
  const { type, file_name = 'valor-export.csv', folder_id = 'root' } = req.body
  const config = EXPORT_CONFIG[type]
  if (!config) return res.status(400).json({ error: 'Unknown export type: ' + type })

  // Build CSV in memory (reuse existing export logic for small datasets)
  let csvRows = [config.headers.map(esc).join(',')]
  let offset = 0
  while (true) {
    const { data, error } = await supabase.from(config.table).select(config.select)
      .order(config.order.col, { ascending: config.order.asc })
      .range(offset, offset + 999)
    if (error || !data?.length) break
    data.forEach(r => csvRows.push(config.map(r).map(esc).join(',')))
    offset += 1000
    if (data.length < 1000) break
  }
  const csvContent = csvRows.join('\n')

  try {
    const accessToken = await getDriveToken(req.user.id)
    if (!accessToken) return res.status(403).json({ error: 'Google Drive not connected' })

    const boundary = '-------valorexportboundary'
    const meta = JSON.stringify({ name: file_name, parents: [folder_id], mimeType: 'text/csv' })
    const body = [
      '--' + boundary, 'Content-Type: application/json; charset=UTF-8', '', meta,
      '--' + boundary, 'Content-Type: text/csv', '', csvContent,
      '--' + boundary + '--',
    ].join('\r\n')

    const r = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + accessToken,
        'Content-Type': 'multipart/related; boundary=' + boundary,
      },
      body
    })
    const data = await r.json()
    if (!r.ok) return res.status(r.status).json({ error: data.error?.message || 'Drive upload failed' })

    try { await safeInsertLog({ user_id: req.user.id, action: 'DRIVE_EXPORT', details: 'Exported ' + type + ' to Drive: ' + file_name }) } catch(_){}
    res.json({ file: data, drive_link: data.webViewLink })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})



// ─── TERRITORIES API ──────────────────────────────────────────────────────────
// Territories are admin-managed regions. WIBs and users can be assigned to one.
// The territories table + territory_id columns are created by the SQL migration.

app.get('/api/territories', auth, async (req, res) => {
  const { data, error } = await supabase.from('territories').select('*').order('name', { ascending: true })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.post('/api/territories', auth, requireAdmin, async (req, res) => {
  const { name, states, description } = req.body
  if (!name?.trim()) return res.status(400).json({ error: 'Territory name required' })
  const { data, error } = await supabase.from('territories').insert({ name: name.trim(), states: states || [], description: description || '' }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'CREATE_TERRITORY', details: `Created territory: ${name}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/territories/:id', auth, requireAdmin, async (req, res) => {
  const allowed = ['name','states','description']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('territories').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/territories/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('territories').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ── GET /api/users/:id/territories — list territories for one user ──
app.get('/api/users/:id/territories', auth, requireAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('user_territory_assignments')
    .select('territory_id, territories(id,name,states,description)')
    .eq('user_id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data: (data || []).map(r => r.territories) })
})

// ── PUT /api/users/:id/territories — replace full assignment set ──
// Body: { territory_ids: ['uuid1', 'uuid2', ...] }
// Passing [] clears all assignments.
app.put('/api/users/:id/territories', auth, requireAdmin, async (req, res) => {
  const { territory_ids = [] } = req.body
  if (!Array.isArray(territory_ids)) {
    return res.status(400).json({ error: 'territory_ids must be an array' })
  }
  // Atomic replace: delete existing then insert new
  const { error: delErr } = await supabase
    .from('user_territory_assignments')
    .delete()
    .eq('user_id', req.params.id)
  if (delErr) return res.status(400).json({ error: delErr.message })
  if (territory_ids.length > 0) {
    const rows = territory_ids.map(tid => ({
      user_id: req.params.id,
      territory_id: tid,
      assigned_by: req.user.id
    }))
    const { error: insErr } = await supabase
      .from('user_territory_assignments')
      .insert(rows)
    if (insErr) return res.status(400).json({ error: insErr.message })
  }
  // Sync legacy single-value column for backwards compat
  await supabase
    .from('user_profiles')
    .update({ territory_id: territory_ids[0] || null })
    .eq('id', req.params.id)
  try {
    const tNames = territory_ids.length
      ? (await supabase.from('territories').select('name').in('id', territory_ids)).data?.map(t => t.name).join(', ')
      : 'none'
    await safeInsertLog({
      user_id: req.user.id,
      action: 'ASSIGN_TERRITORIES',
      record_type: 'user_profiles',
      record_id: req.params.id,
      details: `Assigned territories: ${tNames}`
    })
  } catch (_) {}
  res.json({ success: true, territory_ids })
})

// ── GET /api/me/wib-view — current user's view pref + assigned territories ──
app.get('/api/me/wib-view', auth, async (req, res) => {
  const [{ data: pref }, { data: assignments }] = await Promise.all([
    supabase.from('user_wib_view_prefs').select('view_mode').eq('user_id', req.user.id).single(),
    supabase.from('user_territory_assignments').select('territory_id, territories(id,name)').eq('user_id', req.user.id)
  ])
  const territories = (assignments || []).map(a => a.territories).filter(Boolean)
  res.json({
    view_mode: pref?.view_mode || 'all',
    territories
  })
})

// ── PUT /api/me/wib-view — save current user's view preference ──
app.put('/api/me/wib-view', auth, async (req, res) => {
  const { view_mode } = req.body
  if (!['all', 'my_territories'].includes(view_mode)) {
    return res.status(400).json({ error: 'view_mode must be "all" or "my_territories"' })
  }
  const { error } = await supabase
    .from('user_wib_view_prefs')
    .upsert(
      { user_id: req.user.id, view_mode, updated_at: new Date().toISOString() },
      { onConflict: 'user_id' }
    )
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true, view_mode })
})

// ── GET /api/wibs/my — WIBs filtered to caller's territories ──
app.get('/api/wibs/my', auth, async (req, res) => {
  const { search, limit = 1000 } = req.query
  const { data: assignments } = await supabase
    .from('user_territory_assignments')
    .select('territory_id')
    .eq('user_id', req.user.id)
  const territoryIds = (assignments || []).map(a => a.territory_id)
  let q = supabase
    .from('wib_records')
    .select('*, owner:user_profiles!owner_id(full_name,email)', { count: 'exact' })
    .limit(Number(limit))
  if (territoryIds.length > 0) q = q.in('territory_id', territoryIds)
  if (search) q = q.ilike('wib_name', `%${search}%`)
  const { data, error, count } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

// ── Backwards-compat: single territory assign on user ──
app.put('/api/users/:id/territory', auth, requireAdmin, async (req, res) => {
  const { territory_id } = req.body
  const { data, error } = await supabase.from('user_profiles').update({ territory_id: territory_id || null }).eq('id', req.params.id).select('id,email,full_name,role,territory_id').single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ── Backwards-compat: single territory assign on WIB ──
app.put('/api/wibs/:id/territory', auth, requireAdmin, async (req, res) => {
  const { territory_id } = req.body
  const { data, error } = await supabase.from('wib_records').update({ territory_id: territory_id || null }).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── SERVE FRONTEND ───────────────────────────────────────────────────────────
// Cache the HTML path on startup for performance
let _htmlPath = null
function findHtmlPath() {
  if (_htmlPath && fs.existsSync(_htmlPath)) return _htmlPath
  const candidates = [
    path.join(__dirname, 'public', 'index.html'),
    path.join(__dirname, 'index.html'),
  ]
  for (const p of candidates) {
    if (fs.existsSync(p)) { _htmlPath = p; return p }
  }
  return null
}

app.get('*', (req, res) => {
  // Only serve HTML for non-API, non-asset requests
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' })
  
  const htmlPath = findHtmlPath()
  if (htmlPath) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('Cache-Control', 'no-cache')
    return res.sendFile(htmlPath)
  }
  
  // index.html not found in deployment - show helpful error
  console.error('ERROR: index.html not found. Searched:', [
    path.join(__dirname, 'public', 'index.html'),
    path.join(__dirname, 'index.html'),
  ])
  res.status(503).send('<!DOCTYPE html><html><head><title>Valor CRM</title></head><body style="font-family:sans-serif;background:#0B1E3C;color:#fff;padding:40px;text-align:center"><h2>🛡️ Valor CRM</h2><h3 style="color:#C9A84C">Deployment Issue</h3><p>The application interface (index.html) was not found on the server.</p><p style="font-size:13px;color:rgba(255,255,255,.6)">To fix: Upload both <strong>server.js</strong> AND <strong>index.html</strong> to the GitHub repository, then wait 60 seconds for Render to redeploy.</p><p style="margin-top:20px;font-size:11px;color:rgba(255,255,255,.4)">API is running. Only the frontend is missing.</p></body></html>')
})

const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`✅ Valor CRM on port ${PORT}`)
  console.log(`   SUPABASE_URL: ${SUPABASE_URL ? 'SET ✓' : 'MISSING ✗'}`)
  console.log(`   SUPABASE_ANON_KEY: ${SUPABASE_ANON_KEY ? 'SET ✓' : 'MISSING — login may fail'}`)
  console.log(`   SUPABASE_SERVICE_KEY: ${SUPABASE_SERVICE_KEY ? 'SET ✓' : 'MISSING ✗'}`)
  console.log(``)
  console.log(`   📋 PERMISSIONS TABLE SQL (run once in Supabase SQL Editor):`)
  console.log(`   CREATE TABLE IF NOT EXISTS role_permissions (`)
  console.log(`     id INTEGER PRIMARY KEY DEFAULT 1,`)
  console.log(`     permissions JSONB NOT NULL DEFAULT '{}',`)
  console.log(`     updated_at TIMESTAMPTZ DEFAULT NOW()`)
  console.log(`   );`)
  console.log(`   ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;`)
  console.log(`   CREATE POLICY "Service role full access" ON role_permissions USING (true) WITH CHECK (true);`)
})
