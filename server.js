'use strict'

const express  = require('express')
const { createClient } = require('@supabase/supabase-js')
const path     = require('path')
const fs       = require('fs')
const crypto   = require('crypto')
const app      = express()

// ─── ENVIRONMENT ──────────────────────────────────────────────────────────────
const IS_PROD              = process.env.NODE_ENV === 'production'
const SUPABASE_URL         = process.env.SUPABASE_URL
const SUPABASE_ANON_KEY    = process.env.SUPABASE_ANON_KEY
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('FATAL: Missing SUPABASE_URL or SUPABASE_SERVICE_KEY')
  process.exit(1)
}

const supabase   = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
const authClient = SUPABASE_ANON_KEY
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
  : createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

console.log(`Auth client using: ${SUPABASE_ANON_KEY ? 'ANON KEY ✓' : 'SERVICE KEY (set SUPABASE_ANON_KEY for best results)'}`)

const CORS_ORIGINS = IS_PROD
  ? ['https://valor-crm.onrender.com']
  : ['https://valor-crm.onrender.com', 'http://localhost:3001', 'http://localhost:3000']

// ─── SECURITY HEADERS ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options',    'nosniff')
  res.setHeader('X-Frame-Options',           'DENY')
  res.setHeader('X-XSS-Protection',          '0')
  res.setHeader('Referrer-Policy',           'strict-origin-when-cross-origin')
  res.setHeader('Permissions-Policy',        'camera=(), microphone=(), geolocation=()')
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
  res.removeHeader('X-Powered-By')
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'", "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https: blob:", "font-src 'self' data:",
    "connect-src 'self' https://*.supabase.co https://api.anthropic.com",
    "frame-ancestors 'none'", "form-action 'self'", "base-uri 'self'", "object-src 'none'",
  ].join('; '))
  const origin = req.headers.origin
  if (origin && CORS_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Vary', 'Origin')
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  res.setHeader('Access-Control-Max-Age',       '86400')
  if (req.method === 'OPTIONS') return res.sendStatus(204)
  next()
})

app.use((req, res, next) => {
  if (req.path === '/api/webhooks/aircall') return next()
  express.json({ limit: '10mb', strict: true })(req, res, next)
})

// ─── RATE LIMITING ─────────────────────────────────────────────────────────────
const _loginFallback = new Map()
async function rateLimitLogin(req, res, next) {
  const ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown').substring(0, 45)
  const MAX = 10, WINDOW_MINUTES = 15
  try {
    const since = new Date(Date.now() - WINDOW_MINUTES * 60 * 1000).toISOString()
    const { count, error } = await supabase.from('login_attempts').select('id', { count: 'exact', head: true }).eq('ip_address', ip).gte('attempted_at', since)
    if (!error) {
      if (count >= MAX) return res.status(429).json({ error: `Too many login attempts. Try again in ${WINDOW_MINUTES} minutes.` })
      await supabase.from('login_attempts').insert({ ip_address: ip })
      return next()
    }
  } catch (_) {}
  const now = Date.now(), window = WINDOW_MINUTES * 60 * 1000
  const e = _loginFallback.get(ip) || { count: 0, resetAt: now + window }
  if (now > e.resetAt) { e.count = 0; e.resetAt = now + window }
  e.count++; _loginFallback.set(ip, e)
  if (e.count > MAX) return res.status(429).json({ error: `Too many login attempts. Try again in ${WINDOW_MINUTES} minutes.` })
  next()
}
setInterval(() => { const now = Date.now(); for (const [ip, e] of _loginFallback) if (now > e.resetAt) _loginFallback.delete(ip) }, 30 * 60 * 1000)
;(async () => {
  try {
    await supabase.rpc('exec_ddl', { sql: `CREATE TABLE IF NOT EXISTS login_attempts (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), ip_address TEXT NOT NULL, attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, attempted_at); DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '24 hours';` }).throwOnError()
  } catch (_) {}
})()

const BLOCKED_EXTS  = ['.ts', '.json', '.env', '.md', '.lock', '.sh', '.sql']
const BLOCKED_NAMES = ['server.js', 'server.ts', 'package.json', 'package-lock.json', '.env', 'package.js']
app.use((req, res, next) => {
  const p = req.path.toLowerCase(), filename = p.split('/').pop()
  if (p.startsWith('/api/')) return next()
  if (p === '/' || p === '/index.html' || p === '/favicon.ico') return next()
  if (filename === 'server.js') return res.status(404).send('Not found')
  if (BLOCKED_NAMES.includes(filename)) return res.status(404).send('Not found')
  if (BLOCKED_EXTS.some(ext => p.endsWith(ext))) return res.status(404).send('Not found')
  next()
})

app.use(express.static(path.join(__dirname, 'public'), { index: false, dotfiles: 'deny' }))

let _multer = null
try { _multer = require('multer') } catch (_) { console.warn('multer not installed — run: npm install multer') }
const memUpload = _multer ? _multer({ storage: _multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } }) : null

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
async function auth(req, res, next) {
  try {
    const rawToken = req.headers.authorization?.replace('Bearer ', '').trim()
    if (!rawToken || rawToken.length < 10) return res.status(401).json({ error: 'Authentication required' })
    const { data: { user }, error: authErr } = await authClient.auth.getUser(rawToken)
    if (authErr || !user) return res.status(401).json({ error: 'Session expired. Please sign in again.' })
    try {
      const jwtPayload = JSON.parse(Buffer.from(rawToken.split('.')[1], 'base64url').toString('utf8'))
      const jti = jwtPayload?.jti
      if (jti) { const { data: revoked } = await supabase.from('revoked_tokens').select('jti').eq('jti', jti).single(); if (revoked) return res.status(401).json({ error: 'Session revoked. Please sign in again.' }) }
    } catch (_) {}
    const { data: profile, error: profileErr } = await supabase.from('user_profiles').select('*').eq('id', user.id).single()
    if (profileErr || !profile) return res.status(401).json({ error: 'User profile not found. Contact administrator.' })
    if (profile.is_active === false) return res.status(403).json({ error: 'Account disabled. Contact your administrator.' })
    req.user = profile; req.rawToken = rawToken; next()
  } catch (err) { console.error('Auth middleware error:', err.message); return res.status(500).json({ error: 'Authentication service error' }) }
}

async function revokeToken(rawToken, userId, reason = 'admin_action') {
  try {
    const payload = JSON.parse(Buffer.from(rawToken.split('.')[1], 'base64url').toString('utf8'))
    const jti = payload?.jti, expiresAt = payload?.exp ? new Date(payload.exp * 1000).toISOString() : null
    if (!jti || !expiresAt) return { error: 'No jti in token' }
    const { error } = await supabase.from('revoked_tokens').upsert({ jti, user_id: userId, reason, expires_at: expiresAt }, { onConflict: 'jti', ignoreDuplicates: true })
    return { error }
  } catch (e) { return { error: e.message } }
}

const VALID_ROLES = ['super_admin', 'admin', 'grant_coordinator', 'compliance_mgr', 'team_member', 'external_partner']
const requireAdmin = (req, res, next) => ['super_admin', 'admin'].includes(req.user?.role) ? next() : res.status(403).json({ error: 'Admin access required' })
const requireSuper = (req, res, next) => req.user?.role === 'super_admin' ? next() : res.status(403).json({ error: 'Super admin access required' })
const requireContributor = (req, res, next) => ['super_admin','admin','grant_coordinator','compliance_mgr','team_member'].includes(req.user?.role) ? next() : res.status(403).json({ error: 'Contributor access required — contact your administrator' })
const requireDelete = (req, res, next) => ['super_admin','admin'].includes(req.user?.role) ? next() : res.status(403).json({ error: 'Delete requires Admin or Super Admin access' })

async function logActivity(payload) {
  try { const { error } = await safeInsertLog(payload); if (error) console.warn('logActivity error:', error.message) }
  catch (e) { console.warn('logActivity failed:', e.message) }
}

// ─── SCHEMA CACHE ─────────────────────────────────────────────────────────────
global._hasMetadata = false; global._detailsColumnMissing = false; global._hasRecordType = false
global._hasRecordId = false; global._hasUserId = true; global._safeActivityCols = 'id,action,created_at'

async function refreshSchemaCache() {
  const testCol = async (col) => { try { const { error } = await supabase.from('activity_log').select(col).limit(1); return !error } catch (_) { return false } }
  const [hasDetails, hasMetadata, hasRecordType, hasRecordId, hasUserId] = await Promise.all([testCol('details'),testCol('metadata'),testCol('record_type'),testCol('record_id'),testCol('user_id')])
  global._detailsColumnMissing = !hasDetails; global._hasMetadata = hasMetadata; global._hasRecordType = hasRecordType; global._hasRecordId = hasRecordId; global._hasUserId = hasUserId
  console.log('Schema cache refreshed:', { details: hasDetails, metadata: hasMetadata, record_type: hasRecordType, record_id: hasRecordId, user_id: hasUserId })
  const cols = ['id','action','created_at']
  if (hasDetails) cols.push('details'); if (hasMetadata) cols.push('metadata')
  if (hasRecordType) cols.push('record_type'); if (hasRecordId) cols.push('record_id'); if (hasUserId) cols.push('user_id')
  global._safeActivityCols = cols.join(',')
}
setTimeout(refreshSchemaCache, 500)

async function safeInsertLog(payload) {
  const { metadata, details, record_type, record_id, user_id, ...base } = payload
  if (global._hasUserId !== false && user_id) base.user_id = user_id
  if (global._hasRecordType && record_type) base.record_type = record_type
  if (global._hasRecordId && record_id) base.record_id = record_id
  if (global._hasMetadata) {
    base.metadata = { ...(metadata||{}), content: details, text: details, record_type: record_type||null, record_id: record_id||null }
    if (!global._detailsColumnMissing && details !== undefined) base.details = details
  } else if (!global._detailsColumnMissing) {
    base.details = metadata ? JSON.stringify({ text: details, record_type, record_id, ...metadata }) : (details||'')
  }
  let { data, error } = await supabase.from('activity_log').insert(base).select().single()
  if (error?.message) {
    const msg = error.message; let changed = false
    if (msg.includes('record_type')) { global._hasRecordType = false; delete base.record_type; changed = true }
    if (msg.includes('record_id'))   { global._hasRecordId   = false; delete base.record_id;   changed = true }
    if (msg.includes('details'))     { global._detailsColumnMissing = true; delete base.details; changed = true }
    if (msg.includes('metadata'))    { global._hasMetadata   = false; delete base.metadata; changed = true }
    if (msg.includes('user_id'))     { global._hasUserId     = false; delete base.user_id; changed = true }
    if (changed) {
      const safeCols = ['id','action','created_at']
      if (!global._detailsColumnMissing) safeCols.push('details'); if (global._hasMetadata) safeCols.push('metadata')
      if (global._hasRecordType) safeCols.push('record_type'); if (global._hasRecordId) safeCols.push('record_id')
      if (global._hasUserId !== false) safeCols.push('user_id')
      global._safeActivityCols = safeCols.join(',')
      const retry = await supabase.from('activity_log').insert(base).select().single()
      return { data: retry.data, error: retry.error }
    }
  }
  return { data, error }
}

function parseLogRow(row) {
  if (!row) return row; if (row.metadata) return row
  try { const parsed = JSON.parse(row.details || '{}'); if (typeof parsed === 'object' && parsed !== null) return { ...row, metadata: parsed, details: parsed.text || row.details } } catch (_) {}
  return row
}

app.post('/api/refresh-schema', auth, requireAdmin, async (req, res) => {
  await refreshSchemaCache()
  res.json({ success: true, details_column: !global._detailsColumnMissing ? 'accessible' : 'missing — using metadata column fallback (OK)', metadata_column: global._hasMetadata ? 'accessible' : 'missing', message: 'Schema status refreshed.', sql_fix: "SELECT pg_notify('pgrst', 'reload schema');" })
})

// ─── LOGIN / LOGOUT ───────────────────────────────────────────────────────────
app.post('/api/login', rateLimitLogin, async (req, res) => {
  try {
    const { email, password } = req.body || {}
    if (!email?.trim() || !password) return res.status(400).json({ error: 'Email and password required' })
    const cleanEmail = email.trim().toLowerCase()
    const { data, error } = await authClient.auth.signInWithPassword({ email: cleanEmail, password })
    if (error) return res.status(401).json({ error: 'Invalid email or password' })
    if (!data?.session?.access_token) return res.status(500).json({ error: 'Authentication failed — no session returned.' })
    const { data: profile, error: pe } = await supabase.from('user_profiles').select('*').eq('id', data.user.id).single()
    if (pe || !profile) return res.status(401).json({ error: 'User profile not found. Contact administrator.' })
    if (profile.is_active === false) return res.status(403).json({ error: 'Account disabled. Contact your administrator.' })
    try { await supabase.from('user_profiles').update({ last_login_at: new Date().toISOString() }).eq('id', data.user.id) } catch (_) {}
    try { await supabase.from('activity_log').insert({ user_id: data.user.id, action: 'USER_LOGIN', details: `Login from ${req.headers['x-forwarded-for']?.split(',')[0] || 'unknown'}` }) } catch (_) {}
    return res.json({ token: data.session.access_token, user: profile })
  } catch (err) {
    const msg = err.message || ''
    if (msg.includes('email') || msg.includes('Email')) return res.status(401).json({ error: 'Email not confirmed. Contact your administrator.' })
    if (msg.includes('Invalid') || msg.includes('invalid')) return res.status(401).json({ error: 'Invalid email or password' })
    if (msg.includes('fetch') || msg.includes('network') || msg.includes('Network')) return res.status(503).json({ error: 'Cannot connect to authentication service. Try again.' })
    return res.status(500).json({ error: `Login error: ${msg || 'Unknown.'}` })
  }
})
app.post('/api/logout', auth, async (req, res) => {
  try { await authClient.auth.signOut() } catch (_) {}
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'USER_LOGOUT', details: 'Signed out' }) } catch (_) {}
  res.json({ success: true })
})
app.get('/api/me', auth, (req, res) => res.json(req.user))
app.get('/api/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString(), env: { url: !!SUPABASE_URL, anon: !!SUPABASE_ANON_KEY, anon_prefix: SUPABASE_ANON_KEY ? SUPABASE_ANON_KEY.substring(0,15)+'...' : 'NOT SET', service: !!SUPABASE_SERVICE_KEY } }))

app.post('/api/change-password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body
    if (!new_password || new_password.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' })
    const { error: authErr } = await authClient.auth.signInWithPassword({ email: req.user.email, password: current_password })
    if (authErr) return res.status(401).json({ error: 'Current password is incorrect' })
    const { error } = await supabase.auth.admin.updateUserById(req.user.id, { password: new_password })
    if (error) return res.status(400).json({ error: error.message })
    try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CHANGE_PASSWORD', details: 'User changed own password' }) } catch (_) {}
    res.json({ success: true })
  } catch (err) { res.status(500).json({ error: 'Password change failed. Please try again.' }) }
})

app.post('/api/users/:id/reset-password', auth, requireAdmin, async (req, res) => {
  try {
    const { data: target } = await supabase.from('user_profiles').select('email').eq('id', req.params.id).single()
    if (!target) return res.status(404).json({ error: 'User not found' })
    const { data: linkData, error: linkErr } = await supabase.auth.admin.generateLink({ type: 'recovery', email: target.email })
    if (!linkErr && linkData) {
      try { await safeInsertLog({ user_id: req.user.id, action: 'RESET_PASSWORD', details: 'Reset link sent to: ' + target.email }) } catch (_) {}
      return res.json({ success: true, method: 'magic_link', message: `Password reset email sent to ${target.email}. Link expires in 1 hour.` })
    }
    const tmpPwd = crypto.randomBytes(16).toString('base64url')
    const { error: pwdErr } = await supabase.auth.admin.updateUserById(req.params.id, { password: tmpPwd })
    if (pwdErr) return res.status(400).json({ error: pwdErr.message })
    try { await safeInsertLog({ user_id: req.user.id, action: 'RESET_PASSWORD', details: 'Temp password set for: ' + target.email }) } catch (_) {}
    res.json({ success: true, method: 'temporary_password', temporary_password: tmpPwd, message: `Temp password set for ${target.email}. Share via secure channel only.` })
  } catch (err) { res.status(500).json({ error: err.message }) }
})

// ─── WIBs ─────────────────────────────────────────────────────────────────────
app.get('/api/wibs', auth, async (req, res) => {
  const { state, status, search, limit = 200, offset = 0 } = req.query
  let q = supabase.from('wib_records').select('*, owner:user_profiles!owner_id(full_name,email)', { count: 'exact' })
  if (state)  q = q.eq('state', state)
  if (status) q = q.eq('status', status)
  if (search) {
    const s = `%${search}%`
    q = q.or(`wib_name.ilike.${s},wib_email.ilike.${s},wib_phone.ilike.${s},state.ilike.${s},notes.ilike.${s}`)
  }
  q = q.order('call_priority_score', { ascending: false }).range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q; if (error) return res.status(400).json({ error: error.message }); res.json({ data, count })
})
app.get('/api/wibs/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('wib_records').select('*, owner:user_profiles!owner_id(full_name,email)').eq('id', req.params.id).single()
  if (error) return res.status(404).json({ error: 'Not found' }); res.json(data)
})
app.post('/api/wibs', auth, async (req, res) => {
  const A = ['wib_name','short_name','state','status','wib_phone','wib_email','website','max_award_per_ein','match_requirement_pct','wib_type','source_url','google_drive_folder_url','next_steps','blockers','notes','iwt_program_active','independent_creation_logged','last_verified_date','call_priority_score']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  if (!body.wib_name?.trim()) return res.status(400).json({ error: 'WIB name required' })
  if (!body.source_url?.trim()) return res.status(400).json({ error: 'Source URL required (public government page)' })
  const { data, error } = await supabase.from('wib_records').insert({ ...body, owner_id: req.user.id }).select('*, owner:user_profiles!owner_id(full_name,email)').single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'CREATE_WIB', record_type: 'wib_records', record_id: data.id, details: `Created: ${data.wib_name}` }) } catch (_) {}
  res.json(data)
})
app.put('/api/wibs/:id', auth, async (req, res) => {
  const A = ['wib_name','short_name','state','status','wib_phone','wib_email','website','max_award_per_ein','match_requirement_pct','wib_type','source_url','google_drive_folder_url','next_steps','blockers','notes','iwt_program_active','independent_creation_logged','last_verified_date','call_priority_score']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  const { data, error } = await supabase.from('wib_records').update(body).eq('id', req.params.id).select('*, owner:user_profiles!owner_id(full_name,email)').single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'UPDATE_WIB', record_type: 'wib_records', record_id: req.params.id, details: `Updated: ${data.wib_name}` }) } catch (_) {}
  res.json(data)
})
app.delete('/api/wibs/:id', auth, requireAdmin, async (req, res) => {
  const { data: wib } = await supabase.from('wib_records').select('wib_name').eq('id', req.params.id).single()
  const { error } = await supabase.from('wib_records').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'DELETE_WIB', details: `Deleted: ${wib?.wib_name}` }) } catch (_) {}
  res.json({ success: true })
})

// ─── COMPANIES CRUD ───────────────────────────────────────────────────────────
app.post('/api/companies/dedup', auth, requireAdmin, async (req, res) => {
  const { data: all, error } = await supabase.from('companies').select('*').order('created_at')
  if (error) return res.status(400).json({ error: error.message })
  const groups = {}
  for (const c of (all||[])) { const key = c.company_name.trim().toLowerCase().replace(/[^a-z0-9]/g,'').substring(0,30); if (!groups[key]) groups[key]=[]; groups[key].push(c) }
  let merged = 0, deleted = 0, errors = []
  for (const [,group] of Object.entries(groups)) {
    if (group.length < 2) continue
    const keeper = group[0], dupes = group.slice(1), patch = {}
    for (const d of dupes) for (const [k,v] of Object.entries(d)) if (v && !keeper[k] && !['id','created_at','updated_at'].includes(k)) patch[k]=v
    if (Object.keys(patch).length) { const { error: pErr } = await supabase.from('companies').update(patch).eq('id',keeper.id); if (pErr) errors.push(pErr.message); else merged++ }
    for (const d of dupes) {
      await supabase.from('locations').update({ company_id: keeper.id }).eq('company_id', d.id)
      await supabase.from('applications').update({ company_id: keeper.id }).eq('company_id', d.id)
      const { error: dErr } = await supabase.from('companies').delete().eq('id', d.id); if (!dErr) deleted++
    }
  }
  res.json({ merged, deleted, errors, total_groups: Object.values(groups).filter(g=>g.length>1).length })
})
app.get('/api/companies', auth, async (req, res) => {
  const { search, status, limit = 200, offset = 0 } = req.query
  let q = supabase.from('companies').select('*', { count: 'exact' })
  if (status) q = q.eq('status', status)
  if (search) {
    const s = `%${search}%`
    q = q.or(`company_name.ilike.${s},primary_contact_email.ilike.${s},primary_contact_phone.ilike.${s},primary_contact_name.ilike.${s},notes.ilike.${s},domain.ilike.${s}`)
  }
  q = q.order('company_name').range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q; if (error) return res.status(400).json({ error: error.message }); res.json({ data, count })
})
app.post('/api/companies', auth, async (req, res) => {
  const A = ['company_name','company_type','status','fein','domain','employee_count_total','avg_hourly_wage','primary_contact_name','primary_contact_email','primary_contact_phone','training_needs','notes','rating','is_25_pct_operator','supported_by']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  if (!body.company_name?.trim()) return res.status(400).json({ error: 'Company name required' })
  const nameClean = body.company_name.trim().toLowerCase()

  // ── Phase 1: name / domain / email match (existing logic) ─────────────────
  const { data: byName }   = await supabase.from('companies').select('id,company_name,domain,primary_contact_email,primary_contact_phone,status,notes,created_at').ilike('company_name', `%${nameClean.substring(0,20)}%`).limit(5)
  const { data: byDomain } = body.domain ? await supabase.from('companies').select('id,company_name,domain,primary_contact_email,primary_contact_phone,status,notes,created_at').ilike('domain', `%${body.domain.replace(/^https?:\/\//,'').split('/')[0]}%`).limit(3) : { data: [] }
  const { data: byEmail }  = body.primary_contact_email ? await supabase.from('companies').select('id,company_name,domain,primary_contact_email,primary_contact_phone,status,notes,created_at').eq('primary_contact_email', body.primary_contact_email).limit(3) : { data: [] }

  // ── Phase 2: phone match (new — catches duplicates the old logic missed) ───
  const { data: byPhone }  = body.primary_contact_phone ? await supabase.from('companies').select('id,company_name,domain,primary_contact_email,primary_contact_phone,status,notes,created_at').eq('primary_contact_phone', body.primary_contact_phone).limit(3) : { data: [] }

  // ── Phase 3: address footprint match via notes field ─────────────────────
  // Extract a meaningful address fragment from the incoming notes block (first
  // street number + word, e.g. "123 Main") for loose matching.
  let byAddress = { data: [] }
  if (body.notes) {
    const addrMatch = body.notes.match(/Address:\s*(\d+\s+\w+)/i)
    if (addrMatch) {
      const addrFrag = addrMatch[1].trim()
      byAddress = await supabase.from('companies').select('id,company_name,domain,primary_contact_email,primary_contact_phone,status,notes,created_at').ilike('notes', `%${addrFrag}%`).limit(3)
    }
  }

  const deduped = [...new Map([
    ...(byName||[]), ...(byDomain||[]), ...(byEmail||[]),
    ...(byPhone||[]), ...(byAddress.data||[]),
  ].map(d=>[d.id,d])).values()]

  const match = deduped.find(d => {
    const existName = d.company_name.trim().toLowerCase()
    if (existName === nameClean) return true
    if (existName.substring(0,25) === nameClean.substring(0,25)) return true
    if (body.domain && d.domain && d.domain.toLowerCase().includes(body.domain.replace(/^https?:\/\//,'').split('/')[0].toLowerCase())) return true
    if (body.primary_contact_email && d.primary_contact_email === body.primary_contact_email) return true
    if (body.primary_contact_phone && d.primary_contact_phone === body.primary_contact_phone) return true
    return false
  })

  // ── Merge path ────────────────────────────────────────────────────────────
  if (req.body.merge === true && req.body.merge_into_id) {
    const mergeId = req.body.merge_into_id
    const { data: existing } = await supabase.from('companies').select('*').eq('id', mergeId).single()
    if (!existing) return res.status(404).json({ error: 'Target company not found' })
    const mergePayload = {}
    for (const [k,v] of Object.entries(body)) if (v && !existing[k]) mergePayload[k] = v
    mergePayload.last_contact_date = new Date().toISOString()
    const { data: merged, error: mergeErr } = await supabase.from('companies').update(mergePayload).eq('id', mergeId).select().single()
    if (mergeErr) return res.status(400).json({ error: mergeErr.message })
    try { await safeInsertLog({ user_id: req.user.id, action: 'MERGE_COMPANY', record_type: 'companies', record_id: mergeId, details: `Merged: ${body.company_name} into ${existing.company_name}` }) } catch (_) {}
    return res.json({ merged: true, data: merged })
  }

  // ── Duplicate interceptor — return full payload so frontend modal can offer
  //    Merge / Delete-Cancel / Continue-Adding options ──────────────────────
  if (match && req.body.force !== true) {
    return res.status(409).json({
      duplicate: true,
      message: 'Duplicate record detected',
      existing: {
        id:                    match.id,
        company_name:          match.company_name,
        primary_contact_phone: match.primary_contact_phone || null,
        primary_contact_email: match.primary_contact_email || null,
        domain:                match.domain                || null,
        status:                match.status                || null,
        notes:                 match.notes                 || null,
        created_at:            match.created_at            || null,
      },
    })
  }

  const { data, error } = await supabase.from('companies').insert(body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'CREATE_COMPANY', record_type: 'companies', record_id: data.id, details: `Created: ${data.company_name}` }) } catch (_) {}
  res.json(data)
})
app.put('/api/companies/:id', auth, async (req, res) => {
  const A = ['company_name','company_type','status','fein','domain','employee_count_total','avg_hourly_wage','primary_contact_name','primary_contact_email','primary_contact_phone','training_needs','notes','rating']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  const { data, error } = await supabase.from('companies').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message }); res.json(data)
})
app.delete('/api/companies/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('companies').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message }); res.json({ success: true })
})

// ─── LOCATIONS ────────────────────────────────────────────────────────────────
app.get('/api/locations', auth, async (req, res) => {
  const { state, status, wib_id, search, limit = 200, offset = 0 } = req.query
  let q = supabase.from('locations').select('*, parent_company:companies(company_name), wib:wib_records(wib_name,state)', { count: 'exact' })
  if (state) q=q.eq('state',state); if (status) q=q.eq('status',status); if (wib_id) q=q.eq('wib_id',wib_id); if (search) q=q.ilike('location_name',`%${search}%`)
  q = q.order('location_name').range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q; if (error) return res.status(400).json({ error: error.message }); res.json({ data, count })
})
app.post('/api/locations', auth, async (req, res) => {
  const A = ['location_name','state','county','city','status','employee_count','company_id','wib_id','notes','address']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  if (!body.location_name?.trim()) return res.status(400).json({ error: 'Location name required' })
  const { data, error } = await supabase.from('locations').insert(body).select().single()
  if (error) return res.status(400).json({ error: error.message }); res.json(data)
})
app.put('/api/locations/:id', auth, async (req, res) => {
  const A = ['location_name','state','county','city','status','employee_count','notes','address']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  const { data, error } = await supabase.from('locations').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message }); res.json(data)
})
app.delete('/api/locations/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('locations').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message }); res.json({ success: true })
})

// ─── FUNDING ──────────────────────────────────────────────────────────────────
app.get('/api/funding', auth, async (req, res) => {
  const { status, wib_id, search, limit = 200, offset = 0 } = req.query
  let q = supabase.from('funding_opportunities').select('*, wib:wib_records(id,wib_name,state)', { count: 'exact' })
  if (status) q=q.eq('status',status); if (wib_id) q=q.eq('wib_id',wib_id); if (search) q=q.ilike('opportunity_name',`%${search}%`)
  q = q.order('created_at', { ascending: false }).range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q; if (error) return res.status(400).json({ error: error.message }); res.json({ data, count })
})
app.post('/api/funding', auth, async (req, res) => {
  const A = ['opportunity_name','wib_id','status','program_type','max_award_per_ein','application_deadline','application_link','source_url','notes','independent_creation_logged','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  if (!body.opportunity_name?.trim()) return res.status(400).json({ error: 'Opportunity name required' })
  if (!body.source_url?.trim()) return res.status(400).json({ error: 'Source URL required' })
  const { data, error } = await supabase.from('funding_opportunities').insert(body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'CREATE_FUNDING', record_type: 'funding_opportunities', record_id: data.id, details: `Created: ${data.opportunity_name}` }) } catch (_) {}
  res.json(data)
})
app.put('/api/funding/:id', auth, async (req, res) => {
  const A = ['opportunity_name','status','program_type','max_award_per_ein','application_deadline','application_link','source_url','notes','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  const { data, error } = await supabase.from('funding_opportunities').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message }); res.json(data)
})
app.delete('/api/funding/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('funding_opportunities').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message }); res.json({ success: true })
})

// ─── APPLICATIONS ─────────────────────────────────────────────────────────────
app.get('/api/applications', auth, async (req, res) => {
  const { status, limit = 200, offset = 0 } = req.query
  let q = supabase.from('applications').select('*, company:companies(id,company_name), wib:wib_records(id,wib_name,state), funding_opportunity:funding_opportunities(id,opportunity_name), revenue:revenue_records(fee_model,calculated_success_fee,invoice_status)', { count: 'exact' })
  if (status) q = q.eq('status', status)
  q = q.order('created_at', { ascending: false }).range(+offset, +offset + Math.min(+limit, 200) - 1)
  const { data, error, count } = await q; if (error) return res.status(400).json({ error: error.message }); res.json({ data, count })
})
app.post('/api/applications', auth, async (req, res) => {
  const A = ['company_id','wib_id','funding_opportunity_id','status','award_amount_requested','submission_date','notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  if (!body.company_id) return res.status(400).json({ error: 'Company required' })
  if (!body.wib_id)     return res.status(400).json({ error: 'WIB required' })
  const { data, error } = await supabase.from('applications').insert({ ...body, owner_id: req.user.id }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'CREATE_APPLICATION', record_type: 'applications', record_id: data.id, details: `Created: ${data.application_number}` }) } catch (_) {}
  res.json(data)
})
app.put('/api/applications/:id', auth, async (req, res) => {
  const A = ['status','award_amount_requested','award_amount_approved','submission_date','decision_date','notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  const { data, error } = await supabase.from('applications').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'UPDATE_APPLICATION', record_type: 'applications', record_id: req.params.id, details: `Status: ${body.status || 'updated'}` }) } catch (_) {}
  res.json(data)
})
app.delete('/api/applications/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('applications').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message }); res.json({ success: true })
})

app.get('/api/compliance', auth, async (req, res) => {
  const { data, error } = await supabase.from('v_compliance_alerts').select('*').order('days_until_final_due')
  if (error) return res.status(400).json({ error: error.message }); res.json({ data })
})
app.put('/api/compliance/:id', auth, async (req, res) => {
  const A = ['final_report_submitted','final_report_submitted_date','attendance_sheets_collected','compliance_notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  const { data, error } = await supabase.from('compliance_records').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message }); res.json(data)
})

app.get('/api/revenue/dashboard', auth, async (req, res) => {
  const { data, error } = await supabase.from('v_revenue_dashboard').select('*').single()
  if (error) return res.status(400).json({ error: error.message }); res.json(data || {})
})
app.get('/api/revenue', auth, async (req, res) => {
  const { data, error } = await supabase.from('revenue_records').select('*, company:companies(company_name), wib:wib_records(wib_name)').order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message }); res.json({ data })
})
app.put('/api/revenue/:id', auth, async (req, res) => {
  const A = ['invoice_status','payment_received_date','invoice_sent_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => A.includes(k)))
  const { data, error } = await supabase.from('revenue_records').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await safeInsertLog({ user_id: req.user.id, action: 'UPDATE_REVENUE', record_type: 'revenue_records', record_id: req.params.id, details: `Invoice: ${body.invoice_status || 'updated'}` }) } catch (_) {}
  res.json(data)
})

// ─── NOTES ────────────────────────────────────────────────────────────────────
app.get('/api/notes', auth, async (req, res) => {
  const { record_type, record_id, limit = 50 } = req.query
  const bc = global._safeActivityCols || 'id,action,created_at', uj = global._hasUserId !== false ? ',user:user_profiles!user_id(full_name,email)' : ''
  let q = supabase.from('activity_log').select(bc+uj).eq('action', 'NOTE')
  if (record_type && global._hasRecordType !== false) q = q.eq('record_type', record_type)
  if (record_id   && global._hasRecordId   !== false) q = q.eq('record_id',   record_id)
  q = q.order('created_at', { ascending: false }).limit(Math.min(+limit, 500))
  const { data, error } = await q; if (error) return res.status(400).json({ error: error.message })
  res.json({ data: (data||[]).map(n => parseLogRow(n)) })
})
app.post('/api/notes', auth, async (req, res) => {
  const { record_type, record_id, note_type = 'Note', is_aircall = false } = req.body
  const content = (req.body.content || req.body.details || '').trim()
  if (!content) return res.status(400).json({ error: 'Note content required' })
  const { data, error } = await safeInsertLog({ user_id: req.user.id, action: 'NOTE', record_type: record_type||null, record_id: record_id||null, details: content, metadata: { note_type, is_aircall, content } })
  if (error) return res.status(400).json({ error: error.message })
  const bc2 = global._safeActivityCols || 'id,action,created_at', uj2 = global._hasUserId !== false ? ',user:user_profiles!user_id(full_name,email)' : ''
  const { data: full } = await supabase.from('activity_log').select(bc2+uj2).eq('id', data.id).single()
  res.json(parseLogRow(full || data))
})

app.get('/api/tasks', auth, async (req, res) => {
  const { record_id, limit = 100 } = req.query
  const bc = global._safeActivityCols || 'id,action,created_at', uj = global._hasUserId !== false ? ',user:user_profiles!user_id(full_name)' : ''
  let q = supabase.from('activity_log').select(bc+uj).eq('action', 'TASK')
  if (record_id && global._hasRecordId !== false) q = q.eq('record_id', record_id)
  q = q.order('created_at', { ascending: false }).limit(Math.min(+limit, 500))
  const { data, error } = await q; if (error) return res.status(400).json({ error: error.message })
  res.json({ data: (data||[]).map(t => parseLogRow(t)) })
})
app.post('/api/tasks', auth, async (req, res) => {
  const { title, due_date, record_type, record_id, priority = 'normal', notes, assigned_to } = req.body
  if (!title?.trim()) return res.status(400).json({ error: 'Task title required' })
  const { data, error } = await safeInsertLog({ user_id: req.user.id, action: 'TASK', record_type: record_type||null, record_id: record_id||null, details: title.trim(), metadata: { due_date, priority, notes, done: false, assigned_to, title: title.trim(), created_by: req.user.email } })
  if (error) return res.status(400).json({ error: error.message }); res.json(parseLogRow(data))
})
app.put('/api/tasks/:id', auth, async (req, res) => {
  const { data: existing } = await supabase.from('activity_log').select(global._safeActivityCols||'id,action,created_at').eq('id', req.params.id).single()
  const ep = parseLogRow(existing), nm = { ...(ep?.metadata||{}), ...req.body }
  const up = global._hasMetadata ? { metadata: nm } : { details: JSON.stringify({ text: ep?.metadata?.title||ep?.metadata?.text, ...nm }) }
  const { data, error } = await supabase.from('activity_log').update(up).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message }); res.json(parseLogRow(data))
})

app.get('/api/activity', auth, async (req, res) => {
  const { record_type, record_id, limit = 100 } = req.query
  const bc = global._safeActivityCols||'id,action,created_at', uj = global._hasUserId!==false?',user:user_profiles!user_id(full_name,email)':''
  let q = supabase.from('activity_log').select(bc+uj).neq('action','NOTE').neq('action','TASK')
  if (record_type && global._hasRecordType!==false) q=q.eq('record_type',record_type)
  if (record_id   && global._hasRecordId  !==false) q=q.eq('record_id',record_id)
  q=q.order('created_at',{ascending:false}).limit(Math.min(+limit,200))
  const { data, error } = await q; if (error) return res.status(400).json({error:error.message}); res.json({data:(data||[]).map(r=>parseLogRow(r))})
})
app.get('/api/audit', auth, requireAdmin, async (req, res) => {
  const { limit=100, offset=0 } = req.query
  const bc=global._safeActivityCols||'id,action,created_at', uj=global._hasUserId!==false?',user:user_profiles!user_id(full_name,email)':''
  const { data, error, count } = await supabase.from('activity_log').select(bc+uj,{count:'exact'}).order('created_at',{ascending:false}).range(+offset,+offset+Math.min(+limit,200)-1)
  if (error) return res.status(400).json({error:error.message}); res.json({data:(data||[]).map(r=>parseLogRow(r)),count})
})

// ─── USERS ────────────────────────────────────────────────────────────────────
app.get('/api/users', auth, requireAdmin, async (req, res) => {
  const [{ data:users, error }, { data:assignments }] = await Promise.all([
    supabase.from('user_profiles').select('id,email,full_name,role,title,phone,is_active,created_at,last_login_at,territory_id').order('created_at',{ascending:false}),
    supabase.from('user_territory_assignments').select('user_id,territory_id,territories(id,name)'),
  ])
  if (error) return res.status(400).json({error:error.message})
  const byUser={}; for (const a of (assignments||[])) { if (!byUser[a.user_id]) byUser[a.user_id]=[]; if (a.territories) byUser[a.user_id].push(a.territories) }
  res.json({data:(users||[]).map(u=>({...u,territories:byUser[u.id]||[]}))})
})
app.post('/api/users', auth, requireAdmin, async (req, res) => {
  try {
    const { email, password, full_name, role='team_member', title, phone } = req.body
    if (!email||!password) return res.status(400).json({error:'Email and password required'})
    if (password.length<8) return res.status(400).json({error:'Password must be at least 8 characters'})
    if (!VALID_ROLES.includes(role)) return res.status(400).json({error:'Invalid role'})
    if (role==='super_admin'&&req.user.role!=='super_admin') return res.status(403).json({error:'Only Super Admin can assign the Super Admin role'})
    const { data, error } = await supabase.auth.admin.createUser({email:email.trim().toLowerCase(),password,email_confirm:true,user_metadata:{full_name}})
    if (error) return res.status(400).json({error:error.message})
    await supabase.from('user_profiles').update({full_name:full_name||null,role,title:title||null,phone:phone||null,is_active:true}).eq('id',data.user.id)
    try { await supabase.from('activity_log').insert({user_id:req.user.id,action:'CREATE_USER',details:`Created: ${email} (${role})`}) } catch (_) {}
    const { data:profile } = await supabase.from('user_profiles').select('*').eq('id',data.user.id).single(); res.json({user:profile})
  } catch (err) { res.status(500).json({error:err.message}) }
})
app.put('/api/users/:id', auth, requireAdmin, async (req, res) => {
  try {
    const { full_name, role, title, phone, is_active } = req.body
    if (req.params.id===req.user.id&&is_active===false) return res.status(400).json({error:'Cannot disable your own account'})
    if (is_active===false||(role&&role!=='super_admin')) {
      const { data:t } = await supabase.from('user_profiles').select('role').eq('id',req.params.id).single()
      if (t?.role==='super_admin') { const { count } = await supabase.from('user_profiles').select('*',{count:'exact',head:true}).eq('role','super_admin').eq('is_active',true); if ((count||0)<=1) return res.status(400).json({error:'Cannot disable or demote the only Super Admin'}) }
    }
    const update={}
    if (full_name!==undefined) update.full_name=full_name; if (role!==undefined) update.role=role
    if (title!==undefined) update.title=title; if (phone!==undefined) update.phone=phone; if (is_active!==undefined) update.is_active=is_active
    const { data, error } = await supabase.from('user_profiles').update(update).eq('id',req.params.id).select().single()
    if (error) return res.status(400).json({error:error.message})
    if (is_active===false) { try { await supabase.auth.admin.updateUserById(req.params.id,{ban_duration:'876000h'}) } catch (e) { console.warn('ban failed:',e.message) } }
    if (is_active===true)  { try { await supabase.auth.admin.updateUserById(req.params.id,{ban_duration:'none'})   } catch (e) { console.warn('unban failed:',e.message) } }
    if (role==='super_admin'&&req.user.role!=='super_admin') return res.status(403).json({error:'Only Super Admins can assign the Super Admin role'})
    const cn=[is_active===false?'DISABLED':is_active===true?'RE-ENABLED':'',role?'role set to '+role:''].filter(Boolean).join('; ')
    try { await safeInsertLog({user_id:req.user.id,action:'UPDATE_USER',details:'Updated: '+data.email+(cn?' — '+cn:'')}) } catch (_) {}; res.json(data)
  } catch (err) { res.status(500).json({error:err.message}) }
})
app.delete('/api/users/:id', auth, requireSuper, async (req, res) => {
  try {
    if (req.params.id===req.user.id) return res.status(400).json({error:'Cannot delete your own account'})
    const { data:target } = await supabase.from('user_profiles').select('email,role').eq('id',req.params.id).single()
    if (!target) return res.status(404).json({error:'User not found'})
    if (target.role==='super_admin') { const { count } = await supabase.from('user_profiles').select('*',{count:'exact',head:true}).eq('role','super_admin'); if ((count||0)<=1) return res.status(400).json({error:'Cannot delete the only Super Admin'}) }
    const { error } = await supabase.auth.admin.deleteUser(req.params.id)
    if (error) return res.status(400).json({error:error.message})
    try { await supabase.from('activity_log').insert({user_id:req.user.id,action:'DELETE_USER',details:`DELETED: ${target.email}`}) } catch (_) {}; res.json({success:true})
  } catch (err) { res.status(500).json({error:err.message}) }
})

app.get('/api/contacts', auth, async (req,res)=>{
  const { record_type, record_id, limit=200 } = req.query
  let q=supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name)').eq('action','CONTACT')
  if (record_type) q=q.eq('record_type',record_type); if (record_id) q=q.eq('record_id',record_id)
  q=q.order('created_at',{ascending:false}).limit(+limit)
  const { data, error } = await q; if (error) return res.status(400).json({error:error.message}); res.json({data})
})
app.post('/api/contacts', auth, async (req,res)=>{
  const { name, title, email, phone, record_type, record_id, notes } = req.body
  if (!name?.trim()) return res.status(400).json({error:'Contact name required'})
  const { data, error } = await supabase.from('activity_log').insert({user_id:req.user.id,action:'CONTACT',record_type:record_type||null,record_id:record_id||null,details:name,metadata:{name,title,email,phone,notes}}).select('*, user:user_profiles!user_id(full_name)').single()
  if (error) return res.status(400).json({error:error.message})
  try { await supabase.from('activity_log').insert({user_id:req.user.id,action:'CREATE_CONTACT',record_type,record_id,details:`Added contact: ${name}`}) } catch (_) {}; res.json(data)
})
app.put('/api/contacts/:id', auth, async (req,res)=>{
  const { name, title, email, phone, notes } = req.body
  const { data:ex } = await supabase.from('activity_log').select(global._safeActivityCols||'id,action,created_at').eq('id',req.params.id).single()
  const ep=parseLogRow(ex), merged={...(ep?.metadata||{}),name,title,email,phone,notes}
  const uv=global._hasMetadata?{metadata:merged,details:name||ep?.metadata?.name}:{details:JSON.stringify({text:name,...merged})}
  const { data, error } = await supabase.from('activity_log').update(uv).eq('id',req.params.id).select().single()
  if (error) return res.status(400).json({error:error.message}); res.json(data)
})
app.delete('/api/contacts/:id', auth, requireAdmin, async (req,res)=>{
  const { error } = await supabase.from('activity_log').delete().eq('id',req.params.id).eq('action','CONTACT')
  if (error) return res.status(400).json({error:error.message}); res.json({success:true})
})

app.get('/api/training-providers', auth, async (req,res)=>{
  const { search, limit=200 } = req.query
  let q=supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name)').eq('action','TRAINING_PROVIDER')
  if (search) q=q.ilike('details',`%${search}%`)
  q=q.order('created_at',{ascending:false}).limit(+limit)
  const { data, error } = await q; if (error) return res.status(400).json({error:error.message}); res.json({data})
})
app.post('/api/training-providers', auth, async (req,res)=>{
  const { name, provider_type, website, contact_email, contact_phone, programs, state, notes, status='active' } = req.body
  if (!name?.trim()) return res.status(400).json({error:'Provider name required'})
  const { data, error } = await supabase.from('activity_log').insert({user_id:req.user.id,action:'TRAINING_PROVIDER',details:name,metadata:{name,provider_type,website,contact_email,contact_phone,programs,state,notes,status}}).select('*, user:user_profiles!user_id(full_name)').single()
  if (error) return res.status(400).json({error:error.message}); res.json(data)
})
app.put('/api/training-providers/:id', auth, async (req,res)=>{
  const { data:ex } = await supabase.from('activity_log').select(global._safeActivityCols||'id,action,created_at').eq('id',req.params.id).single()
  const ep=parseLogRow(ex), merged={...(ep?.metadata||{}),...req.body}
  const ud=global._hasMetadata?{details:req.body.name||ex?.details,metadata:merged}:{details:JSON.stringify({text:req.body.name||ex?.details,...merged})}
  const { data, error } = await supabase.from('activity_log').update(ud).eq('id',req.params.id).select().single()
  if (error) return res.status(400).json({error:error.message}); res.json(data)
})
app.delete('/api/training-providers/:id', auth, requireAdmin, async (req,res)=>{
  const { error } = await supabase.from('activity_log').delete().eq('id',req.params.id).eq('action','TRAINING_PROVIDER')
  if (error) return res.status(400).json({error:error.message}); res.json({success:true})
})

app.get('/api/invoices', auth, async (req,res)=>{
  const { status, limit=200 } = req.query
  let q=supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name)').eq('action','INVOICE')
  if (status) q=q.contains('metadata',{status})
  q=q.order('created_at',{ascending:false}).limit(+limit)
  const { data, error } = await q; if (error) return res.status(400).json({error:error.message}); res.json({data})
})
app.post('/api/invoices', auth, async (req,res)=>{
  const { invoice_number, company_name, application_id, amount, fee_model, status='draft', due_date, notes } = req.body
  if (!company_name?.trim()||!amount) return res.status(400).json({error:'Company and amount required'})
  const inv_num=invoice_number||`INV-${Date.now().toString().slice(-6)}`
  const { data, error } = await supabase.from('activity_log').insert({user_id:req.user.id,action:'INVOICE',record_type:'applications',record_id:application_id||null,details:inv_num,metadata:{invoice_number:inv_num,company_name,application_id,amount,fee_model,status,due_date,notes,created_at:new Date().toISOString()}}).select('*, user:user_profiles!user_id(full_name)').single()
  if (error) return res.status(400).json({error:error.message})
  try { await supabase.from('activity_log').insert({user_id:req.user.id,action:'CREATE_INVOICE',details:`Invoice ${inv_num} — $${amount} — ${company_name}`}) } catch (_) {}; res.json(data)
})
app.put('/api/invoices/:id', auth, async (req,res)=>{
  const { data:ex } = await supabase.from('activity_log').select(global._safeActivityCols||'id,action,created_at').eq('id',req.params.id).single()
  const merged={...(ex?.metadata||{}),...req.body}
  const ud=global._hasMetadata?{metadata:merged}:{details:JSON.stringify(merged)}
  const { data, error } = await supabase.from('activity_log').update(ud).eq('id',req.params.id).select().single()
  if (error) return res.status(400).json({error:error.message})
  try { await supabase.from('activity_log').insert({user_id:req.user.id,action:'UPDATE_INVOICE',details:`Invoice ${merged.invoice_number} → ${req.body.status||'updated'}`}) } catch (_) {}; res.json(data)
})

app.get('/api/contracts', auth, async (req,res)=>{
  const { limit=200 } = req.query
  const { data, error } = await supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name)').eq('action','CONTRACT').order('created_at',{ascending:false}).limit(+limit)
  if (error) return res.status(400).json({error:error.message}); res.json({data})
})
app.post('/api/contracts', auth, async (req,res)=>{
  const { company_name, contract_type, value, status='draft', signed_date, expiry_date, notes } = req.body
  if (!company_name?.trim()) return res.status(400).json({error:'Company name required'})
  const cn=`CTR-${Date.now().toString().slice(-6)}`
  const { data, error } = await supabase.from('activity_log').insert({user_id:req.user.id,action:'CONTRACT',details:cn,metadata:{contract_number:cn,company_name,contract_type,value,status,signed_date,expiry_date,notes,created_at:new Date().toISOString()}}).select('*, user:user_profiles!user_id(full_name)').single()
  if (error) return res.status(400).json({error:error.message})
  try { await supabase.from('activity_log').insert({user_id:req.user.id,action:'CREATE_CONTRACT',details:`Contract ${cn} — ${company_name}`}) } catch (_) {}; res.json(data)
})
app.put('/api/contracts/:id', auth, async (req,res)=>{
  const { data:ex } = await supabase.from('activity_log').select(global._safeActivityCols||'id,action,created_at').eq('id',req.params.id).single()
  const merged={...(ex?.metadata||{}),...req.body}, ud=global._hasMetadata?{metadata:merged}:{details:JSON.stringify(merged)}
  const { data, error } = await supabase.from('activity_log').update(ud).eq('id',req.params.id).select().single()
  if (error) return res.status(400).json({error:error.message}); res.json(data)
})
app.delete('/api/contracts/:id', auth, requireAdmin, async (req,res)=>{
  const { error } = await supabase.from('activity_log').delete().eq('id',req.params.id).eq('action','CONTRACT')
  if (error) return res.status(400).json({error:error.message}); res.json({success:true})
})

app.get('/api/grant-awards', auth, async (req,res)=>{
  const { data, error } = await supabase.from('applications').select('*, company:companies(company_name), wib:wib_records(wib_name,state), funding_opportunity:funding_opportunities(opportunity_name), revenue:revenue_records(fee_model,calculated_success_fee,invoice_status,payment_received_date)').in('status',['awarded','active','completed','closed']).order('created_at',{ascending:false})
  if (error) return res.status(400).json({error:error.message}); res.json({data})
})

// ─── PURGE BROKEN IMPORT RECOVERY ROUTE ──────────────────────────────────────
// Phase 1: wipes CMS catalog sentinel rows by name pattern (two ILIKE deletes)
// Phase 2: deduplicates genuine duplicates by phone, email, and address
//          footprint — retains the earliest created_at row, safely nulls
//          foreign-key references on children before deleting the duplicate.
// GET /api/admin/purge-broken-imports  (admin or super_admin only)
app.get('/api/admin/purge-broken-imports', auth, requireAdmin, async (req, res) => {
  let recordsPurged = 0
  try {
    // ── Phase 1: catalog sentinel wipe ────────────────────────────────────────
    const { error: err1 } = await supabase
      .from('companies').delete().ilike('company_name', '%CMS Provider Data Catalog%')
    if (err1) { console.error('[PURGE] err1:', err1.message); return res.status(500).json({ success: false, error: err1.message }) }

    const { error: err2 } = await supabase
      .from('companies').delete().ilike('company_name', '%CMS NH Provider%')
    if (err2) { console.error('[PURGE] err2:', err2.message); return res.status(500).json({ success: false, error: err2.message }) }

    // ── Phase 2: genuine duplicate detection and removal ──────────────────────
    // Fetch all companies ordered oldest-first so the first occurrence in each
    // group is always the one we keep.
    const { data: allCos, error: fetchErr } = await supabase
      .from('companies')
      .select('id,company_name,primary_contact_phone,primary_contact_email,notes,created_at')
      .order('created_at', { ascending: true })

    if (!fetchErr && allCos) {
      // Build a fingerprint for each record. We use three independent signals:
      // normalised phone, normalised email, and the first address fragment
      // found inside the notes block. Any collision on *any single signal*
      // marks the newer row as a duplicate of the earlier one.
      const seen = { phone: new Map(), email: new Map(), addr: new Map() }
      const dupeIds = new Set()

      for (const row of allCos) {
        const phone = (row.primary_contact_phone || '').replace(/\D/g, '').slice(-10)
        const email = (row.primary_contact_email || '').toLowerCase().trim()
        // Extract "123 Main" style fragment from notes
        const addrMatch = (row.notes || '').match(/Address:\s*(\d+\s+\w+)/i)
        const addr = addrMatch ? addrMatch[1].toLowerCase().trim() : ''

        const isDupe = (
          (phone.length >= 7 && seen.phone.has(phone)) ||
          (email.length  >= 4 && seen.email.has(email)) ||
          (addr.length   >= 4 && seen.addr.has(addr))
        )

        if (isDupe) {
          dupeIds.add(row.id)
        } else {
          if (phone.length >= 7) seen.phone.set(phone, row.id)
          if (email.length >= 4) seen.email.set(email, row.id)
          if (addr.length  >= 4) seen.addr.set(addr,  row.id)
        }
      }

      if (dupeIds.size > 0) {
        const dupeArr = [...dupeIds]
        // Null-out FK references in child tables before deleting parents
        await supabase.from('locations').update({ company_id: null }).in('company_id', dupeArr)
        await supabase.from('applications').update({ company_id: null }).in('company_id', dupeArr)
        // Delete duplicates in chunks of 200
        for (let i = 0; i < dupeArr.length; i += 200) {
          const chunk = dupeArr.slice(i, i + 200)
          const { error: delErr } = await supabase.from('companies').delete().in('id', chunk)
          if (!delErr) recordsPurged += chunk.length
          else console.warn('[PURGE] chunk delete error:', delErr.message)
        }
      }
    }

    // Reset the import cache so next import rebuilds a clean map
    global._importCoCache = null

    try {
      await safeInsertLog({
        user_id:     req.user.id,
        action:      'PURGE_BROKEN_IMPORTS',
        record_type: 'companies',
        details:     `Purge by ${req.user.email}: ${recordsPurged} duplicate rows removed`,
      })
    } catch (_) {}

    console.log(`[PURGE] Complete — ${recordsPurged} records removed by ${req.user.email}`)
    return res.json({
      success:       true,
      recordsPurged,
      message:       'All system duplicates have been eliminated.',
    })
  } catch (e) {
    console.error('[PURGE] Fatal:', e.message)
    return res.status(500).json({ success: false, error: e.message })
  }
})

// ─── IMPORT — lightweight JWT auth (multi-batch safe) ─────────────────────────
app.post('/api/import/:type', async (req, res) => {
  const rawToken = req.headers.authorization?.replace('Bearer ', '').trim()
  if (!rawToken || rawToken.length < 10) return res.status(401).json({ error: 'Authentication required' })
  let importUser = null
  try {
    const jwtPayload = JSON.parse(Buffer.from(rawToken.split('.')[1], 'base64url').toString('utf8'))
    if (jwtPayload.exp && jwtPayload.exp < Math.floor(Date.now() / 1000)) return res.status(401).json({ error: 'Session expired. Please sign in again.' })
    const userId = jwtPayload.sub
    if (!userId) return res.status(401).json({ error: 'Invalid token' })
    const { data: profile, error: profileErr } = await supabase.from('user_profiles').select('*').eq('id', userId).single()
    if (profileErr || !profile) return res.status(401).json({ error: 'User profile not found' })
    if (profile.is_active === false) return res.status(403).json({ error: 'Account disabled' })
    importUser = profile
  } catch (_) {
    try {
      const { data: { user }, error: authErr } = await authClient.auth.getUser(rawToken)
      if (authErr || !user) return res.status(401).json({ error: 'Session expired. Please sign in again.' })
      const { data: profile } = await supabase.from('user_profiles').select('*').eq('id', user.id).single()
      if (!profile || profile.is_active === false) return res.status(401).json({ error: 'Access denied' })
      importUser = profile
    } catch (__) { return res.status(401).json({ error: 'Authentication failed' }) }
  }

  const { type } = req.params
  const { rows, batch, totalBatches } = req.body
  if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: 'No rows provided' })
  const results = { created: 0, errors: [], batch: batch || 1, totalBatches: totalBatches || 1 }

  async function bulkInsert(table, records) {
    if (!records.length) return
    const { data, error } = await supabase.from(table).insert(records).select('id')
    if (error) { for (const rec of records) { const { error: e2 } = await supabase.from(table).insert(rec); if (e2) results.errors.push(`Row error: ${e2.message}`); else results.created++ } }
    else results.created += (data || records).length
  }

  try {
    // ═════════════ WIBs ══════════════════════════════════════════════════════
    if (type === 'wibs') {
      const wibStatusMap = {
        'funding available':'funding_available','funding available - have program':'funding_available','funding_available':'funding_available','open':'funding_available','active':'funding_available',
        'follow up needed':'follow_up_needed','follow_up_needed':'follow_up_needed','follow up':'follow_up_needed',
        'pending employer':'pending_employer','pending_employer':'pending_employer','pending':'pending_employer',
        'no reachout completed':'no_reachout_complete','no reachout complete':'no_reachout_complete','no_reachout_complete':'no_reachout_complete','new':'no_reachout_complete','not contacted':'no_reachout_complete',
        'funding not available':'funding_not_available','funding_not_available':'funding_not_available','closed':'funding_not_available','not applicable':'no_reachout_complete',
        'stop applications':'stop_applications','stop_applications':'stop_applications','closed - deadline':'funding_not_available','closed - out of funds':'funding_not_available',
      }
      const stateAbbr = { 'alabama':'AL','alaska':'AK','arizona':'AZ','arkansas':'AR','california':'CA','colorado':'CO','connecticut':'CT','delaware':'DE','florida':'FL','georgia':'GA','hawaii':'HI','idaho':'ID','illinois':'IL','indiana':'IN','iowa':'IA','kansas':'KS','kentucky':'KY','louisiana':'LA','maine':'ME','maryland':'MD','massachusetts':'MA','michigan':'MI','minnesota':'MN','mississippi':'MS','missouri':'MO','montana':'MT','nebraska':'NE','nevada':'NV','new hampshire':'NH','new jersey':'NJ','new mexico':'NM','new york':'NY','north carolina':'NC','north dakota':'ND','ohio':'OH','oklahoma':'OK','oregon':'OR','pennsylvania':'PA','rhode island':'RI','south carolina':'SC','south dakota':'SD','tennessee':'TN','texas':'TX','utah':'UT','vermont':'VT','virginia':'VA','washington':'WA','west virginia':'WV','wisconsin':'WI','wyoming':'WY','district of columbia':'DC','puerto rico':'PR' }
      const getWibField = (row, ...keys) => {
        for (const k of keys) { const v = row[k]??row[k.toLowerCase()]??row[k.toUpperCase()]; if (v!==undefined&&String(v).trim()!==''&&String(v).trim()!=='Not applicable') return String(v).trim() }
        for (const k of keys) { const found=Object.keys(row).find(rk=>rk.toLowerCase().replace(/[^a-z]/g,'').includes(k.toLowerCase().replace(/[^a-z]/g,''))); if (found&&String(row[found]).trim()&&String(row[found]).trim()!=='Not applicable') return String(row[found]).trim() }
        return null
      }
      const valid = []
      for (const row of rows) {
        const name = getWibField(row,'wib_name','Workforce Board','WIB Name','WIB','Name','Record','Board Name')
        if (!name?.trim()) { results.errors.push('Skipped — no WIB name'); continue }
        const rawStatus=(getWibField(row,'Status','WIB Status','Funding Status')||'').toLowerCase().trim()
        const status=wibStatusMap[rawStatus]||'no_reachout_complete'
        const website=getWibField(row,'Website','URL','Web','Homepage','WIB Website')
        const domain=website?website.replace(/^https?:\/\/(www\.)?/,'').split('/')[0]:null
        const cpv=getWibField(row,'Call Priority','call_priority','READONLY In-Network','Priority Score','In-Network Locations')
        const cpn=cpv?parseInt(String(cpv).replace(/[^0-9]/g,''))||0:0
        const wibTypeVal=getWibField(row,'Type','WIB Type','Board Type','Organization Type')
        const zipVal=getWibField(row,'Zipcode','Regional Zipcode','State Zipcode','zip','zipcodes')
        const knownWibKeys=new Set(['Record ID','Workforce Board','WIB Name','WIB','Name','Record','Board Name','WIB Email Address','Email','Short Name','Short','Abbreviation','Status','WIB Status','Funding Status','Type','WIB Type','Board Type','Website','URL','Web','Homepage','Phone','WIB Phone','State','Region','County','Address','Call Priority','Priority','READONLY In-Network','Created','Updated','Owner','Assigned'])
        const noteParts=[]
        const contactCols=Object.entries(row).filter(([k,v])=>/contact.*name|contacts.*name/i.test(k)&&v&&String(v).trim()!=='Not applicable')
        if (contactCols.length) noteParts.push('Contacts: '+contactCols.map(([,v])=>v).join(', '))
        if (wibTypeVal) noteParts.push('WIB Type: '+wibTypeVal); if (zipVal) noteParts.push('Service Area Zipcodes: '+zipVal)
        const extras=Object.entries(row).filter(([k,v])=>!knownWibKeys.has(k)&&v&&String(v).trim()&&String(v).trim()!=='Not applicable')
        if (extras.length) noteParts.push('Additional Data:\n'+extras.map(([k,v])=>k+': '+v).join('\n'))
        const sfn=(()=>{const m=name.match(/^([A-Z]{2})\s*-\s*/);return m?m[1]:null})()
        const rawState=getWibField(row,'State','Region','State/Province','Zipcode > State','State Zipcode > State')
        const stateValue=sfn||(rawState&&rawState.length===2?rawState.toUpperCase():null)||(rawState?stateAbbr[rawState.toLowerCase()]:null)||'US'
        const wr={ wib_name:name, short_name:getWibField(row,'Short Name','Short','Abbreviation','Acronym')||null, state:stateValue, status, wib_email:getWibField(row,'WIB Email Address','Email Address','Email','Contact Email')||null, wib_phone:getWibField(row,'Phone','WIB Phone','Contact Phone','Phone Number')||null, website:domain||null, source_url:website||name||'https://careeronestop.org', notes:noteParts.join('\n')||null, independent_creation_logged:true, owner_id:importUser.id, last_verified_date:new Date().toISOString().split('T')[0] }
        if (cpn>0) wr.call_priority_score=cpn; valid.push(wr)
      }
      for (let i=0;i<valid.length;i+=100) await bulkInsert('wib_records',valid.slice(i,i+100))

    // ═════════════ COMPANIES ════════════════════════════════════════════════
    } else if (type === 'companies') {

      // Single coStatusMap — one declaration, zero duplicates.
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

      const getField = (row, ...keys) => {
        for (const k of keys) { const val=row[k]??row[k.toLowerCase()]??row[k.toUpperCase()]; if (val!==undefined&&String(val).trim()!=='') return String(val).trim() }
        for (const k of keys) { const found=Object.keys(row).find(rk=>rk.toLowerCase().replace(/[^a-z0-9]/g,'').includes(k.toLowerCase().replace(/[^a-z0-9]/g,''))); if (found&&String(row[found]).trim()!=='') return String(row[found]).trim() }
        return null
      }

      // Facility_Name is checked FIRST — it wins over all other name columns.
      const hasFacilityNameKey = rows[0] ? Object.keys(rows[0]).find(k => /^facility[_\s]?name$/i.test(k.trim())) : null
      const nameKey = hasFacilityNameKey || (rows[0] ? Object.keys(rows[0]).find(k => /^(company.?name|record|name|company|employer|organization|account.?name|business.?name)$/i.test(k.trim())) : null)

      const mappedKeys = new Set([
        'Facility_Name','facility_name','FACILITY_NAME','Facility Name','facility name',
        'Address','address','ADDRESS','City','city','CITY','State','state','STATE',
        'Zip','zip','ZIP','Zip Code','zip code','ZIP CODE','Zipcode','zipcode','ZIPCODE',
        'Phone','phone','PHONE','County','county','COUNTY',
        'CMS Certification Number (CCN)','ccn','CCN','Ownership Type','ownership_type','Ownership',
        'Number of Certified Beds','certified_beds','Certified Beds','Number of Residents in Certified Beds','residents','Residents',
        'Provider Type','provider_type','Provider type','Provider Sub-Type','provider_sub_type',
        'Certification Date','certification_date','Participation Date','participation_date',
        'Overall Rating','overall_rating','Health Inspection Rating','health_inspection_rating',
        'QM Rating','qm_rating','Staffing Rating','staffing_rating','RN Staffing Rating','rn_staffing_rating',
        'Provider Name','provider_name','PROVIDER_NAME',
        'Status','Stage','status','stage','Record Stage',
        'Phone numbers','Phone Number','Mobile','Business Phone','primary_contact_phone','Contact Phone','Main Phone',
        'Email addresses','Email Address','Email','email','Primary Email','primary_contact_email','Contact Email','Business Email',
        'Website','website','Domain','domain','URL','Homepage','Web','Site',
        'Contact Name','Contact','Primary Contact','Owner Name','Account Owner','primary_contact_name','Rep','Account Manager','Point of Contact',
        'Employee Count','Employees','Number of Employees','employee_count_total','Staff','Headcount','Size',
        'Notes','Description','Comments','notes','Summary','Bio','About','Details',
        'Type','Company Type','Industry','Sector','Category','company_type',
        'Avg Wage','Average Wage','Avg Hourly Wage','Hourly Rate','avg_hourly_wage',
        'FEIN','EIN','Tax ID','fein','Federal Tax ID','Training Needs','Training','training_needs',
        'Street','Street Address','Address Line 1','Street 1','Mailing Street',
        'Mailing City','Province','Mailing State','Postal Code','Mailing Zip','Country','Mailing Country',
        'LinkedIn','LinkedIn URL','linkedin_url','LinkedIn Profile',
        'Tags','Labels','Categories','tag','label',
        'Owner','Assigned To','Manager','Lead Source','Source','How did you hear','Channel',
        'Record ID','id','ID','Created','Created At','Updated','Updated At',
      ])

      const BAD_NAME_PATTERNS = [
        /^CMS\s+Provider\s+Data\s+Catalog/i, /^CMS\s+NH\s+Provider/i,
        /^CMS\s+HH\s+Provider/i, /^CMS\s+Provider\s+Data/i, /Provider\s+Data\s+Catalog/i,
      ]

      for (const row of rows) {
        let name = hasFacilityNameKey ? (row[hasFacilityNameKey]||'').toString().trim() : null
        if (!name) name = (nameKey&&nameKey!==hasFacilityNameKey?row[nameKey]:null)?.toString().trim() || getField(row,'Company Name','company_name','Record','Name','Company','Employer','Organization','Account Name','Business Name')
        if (!name) { results.errors.push('Skipped — no company name found'); continue }
        if (BAD_NAME_PATTERNS.some(p=>p.test(name))) { results.errors.push(`Skipped — catalog origin string: "${name.substring(0,80)}"`); continue }

        const rawStatus=(getField(row,'Status','Stage','status','stage','Record Stage','Company Stage')||'').toLowerCase().trim()
        const status=coStatusMap[rawStatus]||'prospect'
        const phone=getField(row,'Phone','phone','PHONE','Phone numbers','Phone Number','Mobile','Mobile Phone','primary_contact_phone','Contact Phone','Main Phone','Business Phone')
        const email=getField(row,'Email addresses','Email Address','Email','email','Primary Email','primary_contact_email','Contact Email','Business Email')
        const rawDomain=getField(row,'Website','website','Domain','domain','URL','Homepage','Web','Site')
        const domain=rawDomain?rawDomain.replace(/^https?:\/\/(www\.)?/,'').split('/')[0]:null
        const contactName=getField(row,'Contact Name','Contact','Primary Contact','Owner Name','Account Owner','primary_contact_name','Rep','Account Manager','Point of Contact')
        const empRaw=getField(row,'Employee Count','Employees','Number of Employees','employee_count_total','Number of Certified Beds','certified_beds','Staff','Headcount','Size')
        const employeeCount=empRaw?parseInt(String(empRaw).replace(/[^0-9]/g,''))||null:null
        const notes=getField(row,'Notes','Description','Comments','notes','Summary','Bio','About','Details')
        const rawType=getField(row,'Type','Company Type','Provider Type','provider_type','Ownership Type','ownership_type','Industry','Sector','Category','company_type')

        const insertRow={company_name:name,status}
        if (rawType)       insertRow.company_type         =rawType
        if (domain)        insertRow.domain               =domain
        if (email)         insertRow.primary_contact_email=email
        if (phone)         insertRow.primary_contact_phone=phone
        if (contactName)   insertRow.primary_contact_name =contactName
        if (employeeCount) insertRow.employee_count_total =employeeCount

        const wage=getField(row,'Avg Wage','Average Wage','Avg Hourly Wage','Hourly Rate','avg_hourly_wage')
        if (wage) { const wn=parseFloat(String(wage).replace(/[^0-9.]/g,'')); if (!isNaN(wn)) insertRow.avg_hourly_wage=wn }
        const fein=getField(row,'FEIN','EIN','Tax ID','fein','Federal Tax ID','CMS Certification Number (CCN)','ccn')
        const training=getField(row,'Training Needs','Training','training_needs')
        if (fein)     insertRow.fein           =fein
        if (training) insertRow.training_needs =training

        // Address — CMS exact columns: Address, City, State, Zip
        const streetPart =getField(row,'Address','address','ADDRESS','Street','Street Address','Address Line 1','Street 1','Mailing Street')
        const cityPart   =getField(row,'City','city','CITY','Mailing City')
        const statePart  =getField(row,'State','state','STATE','Province','Mailing State')
        const zipPart    =getField(row,'Zip','zip','ZIP','Zip Code','zip code','Zipcode','zipcode','Postal Code','Mailing Zip')
        const countryPart=getField(row,'Country','Mailing Country')
        const address    =[streetPart,cityPart,statePart,zipPart,countryPart].filter(Boolean).join(', ')

        const linkedin=getField(row,'LinkedIn','LinkedIn URL','linkedin_url','LinkedIn Profile')
        const tags    =getField(row,'Tags','Labels','Categories','tag','label')
        const owner   =getField(row,'Owner','Account Owner','Assigned To','Rep','Manager')
        const source  =getField(row,'Source','Lead Source','How did you hear','Channel')
        const extra   =Object.entries(row).filter(([k,v])=>!mappedKeys.has(k)&&v&&String(v).trim()).map(([k,v])=>`${k}: ${String(v).trim()}`)

        const np=[]
        if (notes)       np.push(notes)
        if (address)     np.push(`Address: ${address}`)
        if (linkedin)    np.push(`LinkedIn: ${linkedin}`)
        if (tags)        np.push(`Tags: ${tags}`)
        if (owner)       np.push(`Assigned To: ${owner}`)
        if (source)      np.push(`Source: ${source}`)
        if (extra.length) np.push('--- Additional Fields ---\n'+extra.join('\n'))
        if (np.length) { insertRow.notes=np.join('\n').substring(0,10000); if (insertRow.notes.length===10000) insertRow.notes+='...' }

        const { data:existingCo } = await supabase.from('companies').select('id').ilike('company_name',insertRow.company_name).limit(1)
        if (existingCo?.[0]) {
          const uf={}; for (const [k,v] of Object.entries(insertRow)) if (v!==null&&v!==''&&k!=='company_name') uf[k]=v
          if (Object.keys(uf).length) { const { error } = await supabase.from('companies').update(uf).eq('id',existingCo[0].id); if (error) results.errors.push(`"${name}": ${error.message}`) }
          results.created++
        } else {
          const { error } = await supabase.from('companies').insert(insertRow)
          if (error) { results.errors.push(`"${name}": ${error.message}`); if (results.errors.length===1) console.error('First company import error:',error.message) }
          else results.created++
        }
      }

    // ═════════════ LOCATIONS ════════════════════════════════════════════════
    } else if (type === 'locations') {
      if (!global._importCoCache||global._importCoCache.size===0) {
        const { data:allCos } = await supabase.from('companies').select('id,company_name')
        global._importCoCache=new Map()
        for (const co of (allCos||[])) { global._importCoCache.set(co.company_name.toLowerCase().trim(),co.id); global._importCoCache.set(co.company_name.toLowerCase().trim().substring(0,25),co.id) }
        console.log('Company cache loaded:',global._importCoCache.size,'entries for locations import')
      }
      const coMap=global._importCoCache
      const findCo=(name)=>{
        if (!name) return null; const lower=name.toLowerCase().trim()
        if (coMap.has(lower)) return coMap.get(lower)
        for (const [k,id] of coMap) if (k.startsWith(lower.substring(0,15))||lower.startsWith(k.substring(0,15))) return id
        return null
      }
      const locStatusMap={'not contacted':'prospect','network member':'prospect','active':'active','prospect':'prospect','inactive':'inactive','open':'prospect'}
      const locBatch=[]
      console.log('LOCATIONS BATCH ROWS:',rows.length,'FIRST:',JSON.stringify(rows[0]||{}))
      for (const row of rows) {
        let name=(row['location_name']||row['Record']||row['Location Name']||row['Location']||row['Name']||row['Facility']||row['Facility Name']||row['Nursing Home']||row['Site Name']||row['record']||row['name']||row['location'])
        name=name?String(name).trim():''
        if (!name) { if (results.errors.length<3) results.errors.push(`DEBUG — CSV headers: ${Object.keys(row).slice(0,8).join(', ')}`); results.errors.push('Skipped — no location name'); continue }
        const parentName=(row['parent_operator']||row['Parent Operator']||row['Parent Company']||row['Company']||row['Operator']||'').trim()
        const company_id=findCo(parentName)
        const rawState=(row['state']||row['State']||row['Province']||'').trim()
        const rawStatus=(row['status']||row['Status']||'prospect').toLowerCase().trim()
        const locRow={location_name:name,owner_id:importUser.id,state:rawState||null,city:(row['city']||row['City']||'').trim()||null,county:(row['county']||row['County']||'').trim()||null,status:locStatusMap[rawStatus]||'prospect',employee_count:(row['employee_count']||row['Employee Count'])?parseInt(row['employee_count']||row['Employee Count'])||null:null,notes:row['notes']||row['Notes']||null,address:row['address']||row['Address']||null}
        if (company_id) locRow.company_id=company_id
        const { data:existingLoc } = await supabase.from('locations').select('id').ilike('location_name',name).limit(1)
        if (existingLoc?.[0]) { const { error } = await supabase.from('locations').update(locRow).eq('id',existingLoc[0].id); if (error) results.errors.push(`"${name}": ${error.message}`); else results.created++ }
        else locBatch.push(locRow)
      }
      for (let i=0;i<locBatch.length;i+=200) {
        const chunk=locBatch.slice(i,i+200)
        const { data:ins, error } = await supabase.from('locations').insert(chunk).select('id')
        if (error) { for (const r of chunk) { const { error:e2 } = await supabase.from('locations').insert(r); if (e2) results.errors.push(`"${r.location_name||'?'}": ${e2.message}`); else results.created++ } }
        else results.created+=(ins||chunk).length
      }

    // ═════════════ FUNDING ════════════════════════════════════════════════════
    } else if (type === 'funding') {
      const fsm={'open':'open','active':'open','available':'open','pending':'pending','pending_employer':'pending_employer','blocked':'blocked','on hold':'blocked','stop':'stop_applications','stop applications':'stop_applications','stop_applications':'stop_applications','closed':'closed_deadline','closed deadline':'closed_deadline','closed_deadline':'closed_deadline','out of funds':'closed_out_of_funds','closed_out_of_funds':'closed_out_of_funds'}
      const valid=[]
      for (const row of rows) {
        const name=(row['opportunity_name']||row['Opportunity Name']||row['Funding Opportunity']||row['Name']||row['Record']||row['Title']||row['Program Name']||row['opportunity name']||row['funding opportunity']||row['name']||row['record'])?.trim()||''
        if (!name) { results.errors.push(results.errors.length<2?`Skipped row — Opportunity Name required. CSV headers found: ${Object.keys(row).slice(0,10).join(', ')}`:'Skipped row — Opportunity Name required'); continue }
        const rawS=(row['status']||row['Status']||'').toLowerCase().trim()
        valid.push({ opportunity_name:name, status:fsm[rawS]||'open', program_type:row['program_type']||row['Program Type']||null, source_url:row['source_url']||row['application_link']||row['Source URL']||row['Application Link']||null, max_award_per_ein:(row['max_award_per_ein']||row['Max Award/EIN']||row['Max per EIN'])?parseFloat(row['max_award_per_ein']||row['Max Award/EIN']||row['Max per EIN'])||null:null, max_award_per_employee:(row['max_award_per_employee']||row['Max per employee'])?parseFloat(row['max_award_per_employee']||row['Max per employee'])||null:null, application_deadline:row['application_deadline']||row['Deadline']||null, blocked_reason:row['blocked_reason']||row['Blocked Reason']||null, promotion_for_participants:row['promotion_for_participants']||row['Promotion']||null, wage_increase_for_participants:row['wage_increase_for_participants']||row['Wage Increase']||null, independent_creation_logged:true })
      }
      for (let i=0;i<valid.length;i+=500) await bulkInsert('funding_opportunities',valid.slice(i,i+500))

    // ═════════════ APPLICATIONS ═══════════════════════════════════════════════
    } else if (type === 'applications') {
      const efc=(record)=>{
        if (!record) return null
        const sc=['AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID','IL','IN','IA','KS','KY','LA','ME','MD','MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ','NM','NY','NC','ND','OH','OK','OR','PA','RI','SC','SD','TN','TX','UT','VT','VA','WA','WV','WI','WY','DC']
        for (const code of sc) for (const pat of [' - '+code+'-',' - '+code+' ',' - '+code+',']) { const idx=record.indexOf(pat); if (idx>3) return record.substring(0,idx).trim() }
        const wp=[' - CO ',' - IW',' - Tri',' - North',' - South',' - East',' - West',' - Greater',' - Central',' - Capital',' - Area ',' - Work',' - NOVA',' - Hampton',' - Permian',' - Gulf',' - Career']
        for (const sep of wp) { const idx=record.indexOf(sep); if (idx>3) return record.substring(0,idx).trim() }
        const di=record.indexOf(' - '); if (di>4&&di<record.length-4) return record.substring(0,di).trim()
        return record.trim()
      }
      if (!global._importCoCache||global._importCoCache.size===0) {
        const { data:allCo } = await supabase.from('companies').select('id,company_name')
        global._importCoCache=new Map()
        for (const co of (allCo||[])) { global._importCoCache.set(co.company_name.toLowerCase().trim(),co.id); global._importCoCache.set(co.company_name.toLowerCase().trim().substring(0,30),co.id) }
        console.log('App import: company cache loaded with',global._importCoCache.size,'entries')
      }
      const companyMap=global._importCoCache
      const { data:allWibs } = await supabase.from('wib_records').select('id,wib_name,short_name,state')
      const wibMap=new Map()
      for (const w of (allWibs||[])) { wibMap.set(w.wib_name.toLowerCase().trim(),w.id); if (w.short_name) wibMap.set(w.short_name.toLowerCase().trim(),w.id) }
      const findCoid=async(name)=>{
        if (!name) return null; const lower=name.toLowerCase().trim()
        if (companyMap.has(lower)) return companyMap.get(lower)
        for (const [key,id] of companyMap) { if (key.startsWith(lower.substring(0,Math.min(20,lower.length)))) return id; if (lower.startsWith(key.substring(0,Math.min(20,key.length)))) return id }
        const p15=lower.substring(0,15); for (const [key,id] of companyMap) if (key.includes(p15)||lower.includes(key.substring(0,15))) return id
        const words=lower.split(/\s+/).filter(w=>w.length>3); let bestId=null,bestScore=0
        for (const [key,id] of companyMap) { const kw=key.split(/\s+/); const shared=words.filter(w=>kw.some(k=>k.startsWith(w.substring(0,6))||w.startsWith(k.substring(0,6)))).length; const score=shared/Math.max(words.length,1); if (score>0.7&&score>bestScore){bestScore=score;bestId=id} }
        if (bestId) return bestId
        try { const { data:d1 } = await supabase.from('companies').select('id').ilike('company_name',lower.substring(0,20)+'%').limit(1); if (d1?.[0]) { companyMap.set(lower,d1[0].id); return d1[0].id } const { data:d2 } = await supabase.from('companies').select('id').ilike('company_name','%'+lower.substring(0,15)+'%').limit(1); if (d2?.[0]) { companyMap.set(lower,d2[0].id); return d2[0].id } } catch (_) {}
        return null
      }
      const findWibId=(name)=>{
        if (!name) return null; const lower=name.toLowerCase().trim()
        if (wibMap.has(lower)) return wibMap.get(lower)
        for (const [key,id] of wibMap) if (key.includes(lower.substring(0,10))||lower.includes(key.substring(0,10))) return id
        return null
      }
      const asm={'intake':'intake','new':'intake','open':'intake','lead':'intake','in progress':'in_progress','in_progress':'in_progress','active':'in_progress','submitted':'submitted','pending':'submitted','under review':'under_review','under_review':'under_review','review':'under_review','awarded':'awarded','won':'awarded','approved':'awarded','funded':'awarded','denied':'denied','rejected':'denied','lost':'denied','closed lost':'denied','withdrawn':'withdrawn','cancelled':'withdrawn','completed':'active','closed':'active'}
      const kak=new Set(['Record ID','Record','Status','Stage','Company','Company Name','Employer','Account','Account Name','WIB','Workforce Board','WIB Name','Board','Notes','Description','Comments','Award Requested','Amount Requested','Award Approved','Amount Approved','Application Approved Amount','Submission Date','Submitted','Decision Date','Decision','Created','Updated','Owner','Record Stage'])
      for (const row of rows) {
        const rn=(row['application_number']||row['Record']||row['Application']||row['Name']||'').trim()
        const rc=(row['company_name']||row['Company']||row['Company Name']||row['Employer']||row['Account']||row['Account Name']||'').trim()||null
        const companyName=rc||efc(rn); if (!companyName) { results.errors.push('Skipped row — no company name'); continue }
        const company_id=await findCoid(companyName)
        const rawWib=(row['WIB']||row['Workforce Board']||row['WIB Name']||row['Board']||'').trim()
        const wibName=rawWib||(rn.split(' - ')[1]||'').trim()||null
        const wib_id=wibName?findWibId(wibName):null
        if (!company_id&&companyName) results.errors.push(`Warning: "${companyName}" not matched to a Company`)
        const rawStatus=(row['status']||row['Status']||row['Stage']||row['Application Stage']||'intake').toLowerCase().trim()
        const status=asm[rawStatus]||'intake'
        const ga=(...ks)=>{for(const k of ks){const v=row[k];if(v&&String(v).trim())return parseFloat(String(v).replace(/[$, ]/g,''))||null};return null}
        const gd=(...ks)=>{for(const k of ks){const v=row[k];if(v&&String(v).trim())return String(v).trim().split('T')[0]};return null}
        const np=[]
        if (rn) np.push(`Application: ${rn}`)
        const nv=row['notes']||row['Notes']||row['Description']||row['Comments']; if (nv) np.push(nv)
        const exts=Object.entries(row).filter(([k,v])=>!kak.has(k)&&v&&String(v).trim()); if (exts.length) np.push('--- Additional ---\n'+exts.map(([k,v])=>k+': '+v).join('\n'))
        const ir={company_id,status,notes:np.join('\n')||null,owner_id:importUser.id}
        if (wib_id) ir.wib_id=wib_id
        const awarded=ga('award_amount_approved','Application Approved Amount','Award Approved','Amount Approved','Approved Amount','Awarded Amount')
        const requested=ga('award_amount_requested','Award Requested','Amount Requested','Requested Amount','Application Amount')
        const subDate=gd('submission_date','Submission Date','Submitted','Submit Date','Date Submitted')
        const decDate=gd('decision_date','Decision Date','Decision','Approved Date','Award Date')
        if (awarded)   ir.award_amount_approved  =awarded
        if (requested) ir.award_amount_requested =requested
        if (subDate)   ir.submission_date=subDate
        if (decDate)   ir.decision_date  =decDate
        const { error } = await supabase.from('applications').insert(ir)
        if (error) { results.errors.push(`"${companyName}": ${error.message}`); if (results.errors.length===1) console.error('First app import error:',error.code,error.message,JSON.stringify(ir)) }
        else results.created++
      }
    } else {
      return res.status(400).json({ error: `Import not supported for type: ${type}` })
    }

    if (!batch||batch===totalBatches) {
      try { await supabase.from('activity_log').insert({user_id:importUser.id,action:'IMPORT',details:`Imported ${results.created} ${type} records (${results.errors.length} errors)`}) } catch (_) {}
    }
    return res.json({ created:results.created, errors:results.errors.slice(0,20), error_count:results.errors.length, truncated:results.errors.length>20, total:rows.length, batch:results.batch, totalBatches:results.totalBatches, first_row_keys:rows[0]?Object.keys(rows[0]).slice(0,8):[] })
  } catch (e) {
    console.error('Import error:', e); res.status(500).json({ error: e.message })
  }
})

app.post('/api/import-test', auth, requireAdmin, async (req, res) => {
  const { row } = req.body; if (!row) return res.status(400).json({ error: 'row required' })
  try {
    const { data, error } = await supabase.from('companies').insert({ company_name: row.company_name||'Test Company '+Date.now(), status: row.status||'prospect' }).select('id,company_name,status').single()
    if (error) return res.json({ success:false, db_error:error.message, db_code:error.code, db_details:error.details, db_hint:error.hint })
    await supabase.from('companies').delete().eq('id', data.id)
    return res.json({ success:true, message:'Test insert worked — DB constraints OK', data })
  } catch (e) { return res.json({ success:false, threw:e.message }) }
})

// ─── CSV ESCAPE HELPER ────────────────────────────────────────────────────────
const esc = (v) => {
  const s = String(v == null ? '' : v)
  const safe = /^[=+\-@\t\r\n]/.test(s) ? "'" + s : s
  return '"' + safe.replace(/"/g, '""') + '"'
}

// ─── EXPORT CONFIG ────────────────────────────────────────────────────────────
const EXPORT_CONFIG = {
  wibs:         { table:'wib_records', select:'wib_name,short_name,state,status,wib_phone,wib_email,website,max_award_per_ein,match_requirement_pct,iwt_program_active,source_url,call_priority_score,last_verified_date,next_steps,blockers', order:{col:'call_priority_score',asc:false}, headers:['WIB Name','Short Name','State','Status','Phone','Email','Website','Max Award/EIN','Match %','IWT Active','Source URL','Score','Last Verified','Next Steps','Blockers'], map:r=>[r.wib_name,r.short_name||'',r.state||'',r.status||'',r.wib_phone||'',r.wib_email||'',r.website||'',r.max_award_per_ein||'',r.match_requirement_pct||'',r.iwt_program_active?'Yes':'No',r.source_url||'',r.call_priority_score||0,r.last_verified_date||'',r.next_steps||'',r.blockers||''] },
  companies:    { table:'companies', select:'company_name,company_type,status,fein,domain,employee_count_total,avg_hourly_wage,primary_contact_name,primary_contact_email,primary_contact_phone,training_needs,notes,rating,created_at', order:{col:'company_name',asc:true}, headers:['Company Name','Type','Status','FEIN','Domain','Employees','Avg Hourly Wage','Contact Name','Contact Email','Contact Phone','Training Needs','Notes','Rating','Created'], map:r=>[r.company_name,r.company_type||'',r.status||'',r.fein||'',r.domain||'',r.employee_count_total||'',r.avg_hourly_wage||'',r.primary_contact_name||'',r.primary_contact_email||'',r.primary_contact_phone||'',r.training_needs||'',r.notes||'',r.rating||'',r.created_at?.split('T')[0]||''] },
  locations:    { table:'locations', select:'location_name,state,county,city,status,employee_count,address,created_at', order:{col:'location_name',asc:true}, headers:['Location','State','County','City','Status','Employees','Address','Created'], map:r=>[r.location_name,r.state||'',r.county||'',r.city||'',r.status||'',r.employee_count||'',r.address||'',r.created_at?.split('T')[0]||''] },
  funding:      { table:'funding_opportunities', select:'opportunity_name,status,program_type,max_award_per_ein,max_award_per_employee,application_deadline,blocked_reason,source_url,created_at', order:{col:'created_at',asc:false}, headers:['Opportunity','Status','Program','Max Award/EIN','Max/Employee','Deadline','Blocked Reason','Source URL','Created'], map:r=>[r.opportunity_name,r.status||'',r.program_type||'',r.max_award_per_ein||'',r.max_award_per_employee||'',r.application_deadline||'',r.blocked_reason||'',r.source_url||'',r.created_at?.split('T')[0]||''] },
  applications: { table:'applications', select:'application_number,status,notes,award_amount_requested,award_amount_approved,submission_date,decision_date,created_at,company:companies!company_id(company_name,domain,primary_contact_email),funding:funding_opportunities!funding_opportunity_id(opportunity_name,status),location:locations!location_id(location_name,state),wib:wib_records!wib_id(wib_name)', order:{col:'created_at',asc:false}, headers:['Application','Company','Domain','Email','Funding Opportunity','Funding Status','Location','State','WIB','Status','Award Requested','Award Approved','Submission Date','Decision Date','Latest Update','Created'], map:r=>[r.application_number||((r.company?.company_name||'')+(r.funding?.opportunity_name?' — '+r.funding.opportunity_name:'')),r.company?.company_name||'',r.company?.domain||'',r.company?.primary_contact_email||'',r.funding?.opportunity_name||'',r.funding?.status||'',r.location?.location_name||'',r.location?.state||'',r.wib?.wib_name||'',r.status||'',r.award_amount_requested||'',r.award_amount_approved||'',r.submission_date||'',r.decision_date||'',(r.notes||'').split('\n')[0].substring(0,100),r.created_at?.split('T')[0]||''] },
  revenue:      { table:'revenue_records', select:'fee_model,grant_award_amount,calculated_success_fee,invoice_status,payment_received_date,created_at', order:{col:'created_at',asc:false}, headers:['Fee Model','Grant Award','Valor Fee','Invoice Status','Payment Date','Created'], map:r=>[r.fee_model||'',r.grant_award_amount||'',r.calculated_success_fee||'',r.invoice_status||'',r.payment_received_date||'',r.created_at?.split('T')[0]||''] },
}
const PAGE_SIZE = 1000

app.get('/api/export/:type', auth, async (req, res) => {
  const { type } = req.params
  if (['users','audit'].includes(type)&&!['super_admin','admin'].includes(req.user.role)) return res.status(403).json({error:'Admin access required for this export'})
  if (type==='users') {
    const { data } = await supabase.from('user_profiles').select('full_name,email,role,title,is_active,created_at')
    const h=['Name','Email','Role','Title','Active','Created'], r=(data||[]).map(r=>[r.full_name||'',r.email||'',r.role||'',r.title||'',r.is_active?'Yes':'No',r.created_at?.split('T')[0]||''])
    res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition',`attachment; filename="valor-users-${new Date().toISOString().split('T')[0]}.csv"`)
    return res.send([h.map(esc).join(','),...r.map(r=>r.map(esc).join(','))].join('\n'))
  }
  if (type==='compliance') {
    const { data } = await supabase.from('v_compliance_alerts').select('*').order('days_until_final_due')
    const h=['Application #','Company','WIB','Status','Award Amount','Training End','Final Report Due','Days Until Due','Report Submitted','Attendance Collected','Notes']
    const r=(data||[]).map(r=>[r.application_number||'',r.company_name||'',r.wib_name||'',r.status||'',r.award_amount_approved||'',r.training_end_date||'',r.final_report_due_date||'',r.days_until_final_due??'',r.final_report_submitted?'Yes':'No',r.attendance_sheets_collected?'Yes':'No',r.compliance_notes||''])
    res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition',`attachment; filename="valor-compliance-${new Date().toISOString().split('T')[0]}.csv"`)
    return res.send([h.map(esc).join(','),...r.map(r=>r.map(esc).join(','))].join('\n'))
  }
  if (type==='audit') {
    const as='action,created_at'+(global._hasRecordType?',record_type':'')+(global._detailsColumnMissing?'':global._hasMetadata?',metadata':',details')+',user:user_profiles!user_id(email)'
    const { data } = await supabase.from('activity_log').select(as).order('created_at',{ascending:false}).limit(2000)
    const h=['Action','User','Details','Record Type','Timestamp'], r=(data||[]).map(r=>[r.action||'',r.user?.email||'',r.details||r.metadata?.text||'',r.record_type||'',r.created_at||''])
    res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition',`attachment; filename="valor-audit-${new Date().toISOString().split('T')[0]}.csv"`)
    return res.send([h.map(esc).join(','),...r.map(r=>r.map(esc).join(','))].join('\n'))
  }
  const config=EXPORT_CONFIG[type]; if (!config) return res.status(400).json({error:`Unknown export type: ${type}`})
  const filename=`valor-${type}-${new Date().toISOString().split('T')[0]}.csv`
  res.setHeader('Content-Type','text/csv; charset=utf-8'); res.setHeader('Content-Disposition',`attachment; filename="${filename}"`); res.setHeader('Transfer-Encoding','chunked'); res.setHeader('Cache-Control','no-store')
  res.write(config.headers.map(esc).join(',')+'\n')
  let offset=0, totalExported=0
  try {
    while (true) {
      const { data, error } = await supabase.from(config.table).select(config.select).order(config.order.col,{ascending:config.order.asc}).range(offset,offset+PAGE_SIZE-1)
      if (error) { res.write(`\n# ERROR: ${error.message}\n`); break }
      if (!data||data.length===0) break
      res.write(data.map(r=>config.map(r).map(esc).join(',')).join('\n')+'\n')
      totalExported+=data.length; offset+=PAGE_SIZE; if (data.length<PAGE_SIZE) break
    }
    safeInsertLog({user_id:req.user.id,action:'EXPORT',details:`Exported ${type} — ${totalExported} records`}).catch(()=>{})
    res.end()
  } catch (e) { console.error('Export stream error:',e.message); res.write(`\n# EXPORT FAILED: ${e.message}\n`); res.end() }
})

app.get('/api/template/:type', auth, (req, res) => {
  const templates = {
    wibs:'WIB Name,Short Name,State,Status,Phone,Email,Website,Max Award,Match %,IWT Active,Source URL',
    companies:'Company Name,Type,Status,FEIN,Domain,Employee Count,Avg Wage,Contact Name,Contact Email,Contact Phone,Training Needs,Notes',
    locations:'Location Name,State,County,City,Status,Employee Count,Address,Notes',
    funding:'Opportunity Name,Status,Program Type,Max Award/EIN,Max/Employee,Deadline,Blocked Reason,Source URL',
    applications:'Company Name,WIB,Funding Opportunity,Status,Award Requested,Award Approved,Submission Date,Decision Date,Notes',
  }
  const csv=templates[req.params.type]; if (!csv) return res.status(400).json({error:`Unknown template type: ${req.params.type}`})
  res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition',`attachment; filename="valor-${req.params.type}-template.csv"`); res.send(csv)
})

// ─── AIRCALL WEBHOOK ──────────────────────────────────────────────────────────
app.post('/api/webhooks/aircall', express.raw({ type:'*/*', limit:'1mb' }), async (req, res) => {
  const secret=process.env.AIRCALL_WEBHOOK_SECRET, sigHeader=req.headers['x-aircall-signature']||''
  if (secret) {
    const computed='sha256='+crypto.createHmac('sha256',secret).update(req.body).digest('hex')
    const sigBuf=Buffer.from(sigHeader.padEnd(computed.length)), compBuf=Buffer.from(computed)
    if (sigBuf.length!==compBuf.length||!crypto.timingSafeEqual(sigBuf,compBuf)) { console.warn('Aircall webhook: signature mismatch'); return res.status(401).json({error:'Invalid webhook signature'}) }
  } else console.warn('AIRCALL_WEBHOOK_SECRET not set')
  let payload; try { payload=JSON.parse(req.body.toString('utf8')) } catch (e) { return res.status(400).json({error:'Invalid JSON in webhook body'}) }
  const { event, data:callData } = payload
  if (!callData?.id) return res.status(400).json({error:'Missing call_id in payload'})
  const callId=String(callData.id)
  const up={call_id:callId,direction:callData.direction||null,duration:callData.duration||null,started_at:callData.started_at?new Date(callData.started_at*1000).toISOString():null,ended_at:callData.ended_at?new Date(callData.ended_at*1000).toISOString():null,recording_url:callData.recording||null,assigned_email:callData.user?.email||null,raw_payload:payload}
  if (callData.user?.email) { const { data:ap } = await supabase.from('user_profiles').select('id').eq('email',callData.user.email).single(); if (ap) up.assigned_to=ap.id }
  const { data:upserted, error:upsertErr } = await supabase.from('aircall_calls').upsert(up,{onConflict:'call_id',ignoreDuplicates:false}).select().single()
  if (upsertErr) { console.error('Aircall upsert error:',upsertErr.message); return res.status(500).json({error:'Failed to store call record'}) }
  if (event==='call.ended'&&upserted.duration&&!upserted.note_id) {
    const cd=upserted.started_at?new Date(upserted.started_at).toLocaleDateString('en-US'):'Unknown'
    const ds=upserted.duration?`${Math.floor(upserted.duration/60)}m ${upserted.duration%60}s`:'Unknown'
    const an=callData.user?.name||callData.user?.email||'Unknown Agent'
    const dir=upserted.direction==='inbound'?'📞 Inbound':'📤 Outbound'
    const rec=upserted.recording_url?`\nRecording: ${upserted.recording_url}`:''
    const nc=[`[AIRCALL NOTE] | ${cd} | ${ds} | ${an}`,`Direction: ${dir}`,`Duration: ${ds}`,rec].filter(Boolean).join('\n')
    if (upserted.assigned_to) {
      const { data:newNote } = await supabase.from('notes').insert({record_type:upserted.record_type||'internal',record_id:upserted.record_id||upserted.assigned_to,content:nc,note_type:'Call Summary',is_aircall:true,aircall_id:callId,created_by:upserted.assigned_to}).select('id').single()
      if (newNote) await supabase.from('aircall_calls').update({note_id:newNote.id,status:'note_created'}).eq('call_id',callId)
    }
  }
  res.status(200).json({received:true,call_id:callId,event})
})

// ─── AI ASSISTANT PROXY ───────────────────────────────────────────────────────
app.post('/api/ai', auth, async (req, res) => {
  const { prompt, context='' } = req.body
  if (!prompt?.trim()) return res.status(400).json({error:'Prompt required'})
  const apiKey=process.env.ANTHROPIC_API_KEY
  if (!apiKey) return res.json({text:'AI Assistant requires an ANTHROPIC_API_KEY environment variable. Add it in your Render dashboard, then redeploy.',error:true})
  function sanitizeAiInput(s) {
    return String(s||'').substring(0,2000).replace(/ignore\s+(previous|all|prior|above)\s+(instructions?|prompts?|context)/gi,'[filtered]').replace(/system\s*prompt/gi,'[filtered]').replace(/you\s+are\s+(?:now|a|an)\s+(?:different|new|another)/gi,'[filtered]').replace(/reveal\s+(?:all|every|the|your)\s+(?:data|records|users|companies)/gi,'[filtered]').replace(/<script[^>]*>.*?<\/script>/gi,'[filtered]').trim()
  }
  const sp=sanitizeAiInput(prompt), sc=sanitizeAiInput(context)
  const oha=new Date(Date.now()-3_600_000).toISOString()
  const { count:aiCount } = await supabase.from('activity_log').select('id',{count:'exact',head:true}).eq('user_id',req.user.id).eq('action','AI_QUERY').gte('created_at',oha)
  if ((aiCount||0)>=50) return res.status(429).json({error:'AI rate limit reached (50 requests/hour).',text:'Rate limit reached. Try again in an hour.'})
  try {
    const response=await fetch('https://api.anthropic.com/v1/messages',{method:'POST',headers:{'Content-Type':'application/json','x-api-key':apiKey,'anthropic-version':'2023-06-01'},body:JSON.stringify({model:'claude-sonnet-4-5',max_tokens:1000,system:'You are an expert workforce grant consultant AI assistant for Valor Workforce Funding LLC. You help staff analyze WIB relationships, employer eligibility, grant funding opportunities, and application status. Never reveal data from other organizations. Only discuss the context provided. Be concise, actionable, and format for CRM display.',messages:[{role:'user',content:`Context: ${sc}\n\nTask: ${sp}`}]})})
    const data=await response.json()
    if (data.error) return res.json({text:`AI Error: ${data.error.message}`,error:true})
    const text=data.content?.[0]?.text||'No response generated.'
    try { await supabase.from('activity_log').insert({user_id:req.user.id,action:'AI_QUERY',details:prompt.substring(0,200)}) } catch (_) {}
    res.json({text})
  } catch (e) { res.status(500).json({error:e.message,text:'AI temporarily unavailable: '+e.message}) }
})

// ─── ROLE PERMISSIONS ─────────────────────────────────────────────────────────
const DEFAULT_PERMISSIONS = {
  view_records:          {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:true,team_member:true,external_partner:true},
  create_wibs_companies: {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:false,team_member:true,external_partner:false},
  edit_wibs_companies:   {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:false,team_member:true,external_partner:false},
  delete_records:        {super_admin:true,admin:true,grant_coordinator:false,compliance_mgr:false,team_member:false,external_partner:false},
  create_edit_apps:      {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:false,team_member:true,external_partner:false},
  view_revenue:          {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:false,team_member:true,external_partner:false},
  manage_invoices:       {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:false,team_member:false,external_partner:false},
  compliance_tracking:   {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:true,team_member:false,external_partner:false},
  notes_tasks:           {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:true,team_member:true,external_partner:false},
  ai_assistant:          {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:true,team_member:true,external_partner:false},
  import_export:         {super_admin:true,admin:true,grant_coordinator:true,compliance_mgr:true,team_member:true,external_partner:false},
  audit_logs:            {super_admin:true,admin:true,grant_coordinator:false,compliance_mgr:false,team_member:false,external_partner:false},
  manage_users:          {super_admin:true,admin:true,grant_coordinator:false,compliance_mgr:false,team_member:false,external_partner:false},
  assign_roles:          {super_admin:true,admin:true,grant_coordinator:false,compliance_mgr:false,team_member:false,external_partner:false},
  assign_super_admin:    {super_admin:true,admin:false,grant_coordinator:false,compliance_mgr:false,team_member:false,external_partner:false},
  system_settings:       {super_admin:true,admin:true,grant_coordinator:false,compliance_mgr:false,team_member:false,external_partner:false},
}
const LOCKED_PERMISSIONS = { view_records:{external_partner:true}, manage_users:{super_admin:true}, assign_super_admin:{super_admin:true}, system_settings:{super_admin:true}, assign_roles:{super_admin:true} }
let _permissionsCache=null
async function loadPermissions() {
  if (_permissionsCache) return _permissionsCache
  try { const { data, error } = await supabase.from('role_permissions').select('*').single(); if (!error&&data?.permissions) { _permissionsCache={...DEFAULT_PERMISSIONS,...data.permissions} } else { _permissionsCache={...DEFAULT_PERMISSIONS} } } catch { _permissionsCache={...DEFAULT_PERMISSIONS} }
  return _permissionsCache
}
async function savePermissions(perms) {
  _permissionsCache=perms
  try { const { error } = await supabase.from('role_permissions').upsert({id:1,permissions:perms,updated_at:new Date().toISOString()}); if (error) console.warn('role_permissions table may not exist yet.') } catch (e) { console.warn('Permissions save failed:',e.message) }
}
app.get('/api/permissions', auth, async (req,res)=>{
  try { const perms=await loadPermissions(); res.json({permissions:perms,locked:LOCKED_PERMISSIONS}) } catch (e) { res.status(500).json({error:e.message}) }
})
app.put('/api/permissions', auth, requireSuper, async (req,res)=>{
  try {
    const { permission, role, value } = req.body
    if (!permission||!role||value===undefined) return res.status(400).json({error:'permission, role, and value required'})
    if (!VALID_ROLES.includes(role)) return res.status(400).json({error:'Invalid role'})
    if (LOCKED_PERMISSIONS[permission]?.[role]!==undefined) return res.status(400).json({error:`The "${permission}" permission for "${role}" is locked`})
    const perms=await loadPermissions(); if (!perms[permission]) return res.status(400).json({error:'Unknown permission key'})
    perms[permission][role]=!!value; await savePermissions(perms)
    try { await logActivity({user_id:req.user.id,action:'UPDATE_PERMISSIONS',details:`Set ${permission}/${role} = ${value}`}) } catch (_) {}
    res.json({success:true,permissions:perms})
  } catch (e) { res.status(500).json({error:e.message}) }
})
function requirePermission(permKey) {
  return async (req,res,next)=>{ try { const perms=await loadPermissions(); const allowed=perms[permKey]?.[req.user?.role]; if (!allowed) return res.status(403).json({error:'You do not have permission to perform this action'}); next() } catch { next() } }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/notifications', auth, async (req,res)=>{
  const { limit=50, unread_only } = req.query
  try {
    let q=supabase.from('notifications').select('*, sender:user_profiles!sender_id(full_name,email)',{count:'exact'}).eq('recipient_id',req.user.id).order('created_at',{ascending:false}).limit(Math.min(+limit,100))
    if (unread_only==='true') q=q.eq('is_read',false)
    const { data, error } = await q; if (error) return res.status(400).json({error:error.message})
    const wa=new Date(Date.now()-7*24*3600*1000).toISOString()
    const [nr,tr]=await Promise.all([supabase.from('activity_log').select('id',{count:'exact',head:true}).eq('action','NOTE').gte('created_at',wa),supabase.from('activity_log').select('id',{count:'exact',head:true}).eq('action','TASK').gte('created_at',wa)])
    const notifications=(data||[]).map(n=>({...n,sender_name:n.sender?.full_name||n.sender?.email||'System'}))
    res.json({data:notifications,unread_count:notifications.filter(n=>!n.is_read).length,activity_summary:{notes_this_week:nr.count||0,tasks_completed:tr.count||0,wibs_contacted:null,apps_submitted:null}})
  } catch (e) { res.status(500).json({error:e.message}) }
})
app.put('/api/notifications/:id/read', auth, async (req,res)=>{ const { error }=await supabase.from('notifications').update({is_read:true}).eq('id',req.params.id).eq('recipient_id',req.user.id); if (error) return res.status(400).json({error:error.message}); res.json({success:true}) })
app.post('/api/notifications/mark-all-read', auth, async (req,res)=>{ const { error }=await supabase.from('notifications').update({is_read:true}).eq('recipient_id',req.user.id).eq('is_read',false); if (error) return res.status(400).json({error:error.message}); res.json({success:true}) })
app.post('/api/notifications/:id/respond', auth, async (req,res)=>{
  const { action } = req.body
  const { data:notif }=await supabase.from('notifications').select('*').eq('id',req.params.id).eq('recipient_id',req.user.id).single()
  if (!notif) return res.status(404).json({error:'Notification not found'})
  await supabase.from('notifications').update({is_read:true,responded_at:new Date().toISOString(),response_action:action}).eq('id',req.params.id)
  res.json({success:true,action})
})
async function createNotification({ recipientId, senderId, type, title, body, recordType, recordId }) {
  try { await supabase.from('notifications').insert({recipient_id:recipientId,sender_id:senderId||null,type:type||'system',title:title||'',body:body||'',record_type:recordType||null,record_id:recordId||null}) }
  catch (e) { console.warn('createNotification failed (non-fatal):',e.message) }
}

// ═══════════════════════════════════════════════════════════════════════════════
// LIVE CHAT — SSE presence, channel messages, DMs
// ═══════════════════════════════════════════════════════════════════════════════
const _presence=new Map(), PRESENCE_TTL=40_000, _sseClients=new Map()
function presenceGC() { const c=Date.now()-PRESENCE_TTL; let changed=false; for (const [uid,info] of _presence) if (info.lastSeen<c) { _presence.delete(uid); changed=true }; if (changed) broadcastPresence() }
setInterval(presenceGC,15_000)
function broadcastPresence() {
  const snapshot=[..._presence.values()].map(p=>({id:p.id,name:p.name,email:p.email,initials:p.initials,lastSeen:p.lastSeen}))
  const payload=`event:presence\ndata:${JSON.stringify(snapshot)}\n\n`
  for (const clients of _sseClients.values()) for (const r of clients) { try { r.write(payload) } catch (_) {} }
}
function broadcastChatMessage(msg,channel) {
  const payload=`event:chat_message\ndata:${JSON.stringify({channel,msg})}\n\n`
  for (const clients of _sseClients.values()) for (const r of clients) { try { r.write(payload) } catch (_) {} }
}
function broadcastDM(msg,senderId,recipientId) {
  const payload=`event:dm\ndata:${JSON.stringify(msg)}\n\n`
  for (const uid of [senderId,recipientId]) { const clients=_sseClients.get(uid)||new Set(); for (const r of clients) { try { r.write(payload) } catch (_) {} } }
}
async function sseAuth(req,res) {
  const rawToken=(req.query.token||'').trim()
  if (!rawToken||rawToken.length<10) { res.status(401).end('Unauthorized'); return null }
  try {
    const { data:{user}, error:authErr }=await authClient.auth.getUser(rawToken)
    if (authErr||!user) { res.status(401).end('Session expired'); return null }
    try { const jp=JSON.parse(Buffer.from(rawToken.split('.')[1],'base64url').toString('utf8')); const jti=jp?.jti; if (jti) { const { data:revoked }=await supabase.from('revoked_tokens').select('jti').eq('jti',jti).single(); if (revoked) { res.status(401).end('Session revoked'); return null } } } catch (_) {}
    const { data:profile, error:profileErr }=await supabase.from('user_profiles').select('*').eq('id',user.id).single()
    if (profileErr||!profile||profile.is_active===false) { res.status(403).end('Account disabled'); return null }
    return profile
  } catch (e) { res.status(500).end('Auth error'); return null }
}
app.get('/api/chat/stream', async (req,res)=>{
  const profile=await sseAuth(req,res); if (!profile) return
  const userId=profile.id
  res.setHeader('Content-Type','text/event-stream'); res.setHeader('Cache-Control','no-cache'); res.setHeader('Connection','keep-alive'); res.setHeader('X-Accel-Buffering','no'); res.flushHeaders()
  if (!_sseClients.has(userId)) _sseClients.set(userId,new Set()); _sseClients.get(userId).add(res)
  _presence.set(userId,{id:userId,name:profile.full_name||profile.email,email:profile.email,initials:(profile.full_name||profile.email||'?').slice(0,2).toUpperCase(),lastSeen:Date.now()})
  broadcastPresence(); res.write(`event:presence\ndata:${JSON.stringify([..._presence.values()])}\n\n`)
  const pingInterval=setInterval(()=>{ try { res.write(': ping\n\n') } catch (_) { cleanup() } },20_000)
  function cleanup() { clearInterval(pingInterval); const set=_sseClients.get(userId); if (set) { set.delete(res); if (set.size===0) { _sseClients.delete(userId); _presence.delete(userId); broadcastPresence() } }; try { res.end() } catch (_) {} }
  req.on('close',cleanup); req.on('error',cleanup); res.on('finish',cleanup)
})
app.post('/api/chat/heartbeat', auth, (req,res)=>{
  const ex=_presence.get(req.user.id)||{id:req.user.id,name:req.user.full_name||req.user.email,email:req.user.email,initials:(req.user.full_name||req.user.email||'?').slice(0,2).toUpperCase()}
  ex.lastSeen=Date.now(); _presence.set(req.user.id,ex); res.json({ok:true,online:_presence.size})
})
app.get('/api/chat/users', auth, async (req,res)=>{ const { data, error }=await supabase.from('user_profiles').select('id,full_name,email,role').eq('is_active',true).neq('id',req.user.id).order('full_name'); if (error) return res.status(400).json({error:error.message}); res.json({data:data||[]}) })
app.get('/api/dm/unread-counts', auth, async (req,res)=>{ const { data, error }=await supabase.from('chat_dm_messages').select('sender_id').eq('recipient_id',req.user.id).eq('is_read',false); if (error) return res.status(400).json({error:error.message}); const counts={}; for (const row of (data||[])) counts[row.sender_id]=(counts[row.sender_id]||0)+1; res.json(counts) })
app.get('/api/chat/:channel', auth, async (req,res)=>{
  const channel=req.params.channel.substring(0,100), limit=Math.min(+(req.query.limit||60),200)
  const { data, error }=await supabase.from('chat_messages').select('*, sender:user_profiles!sender_id(id,full_name,email)').eq('channel',channel).eq('is_deleted',false).order('created_at',{ascending:false}).limit(limit)
  if (error) return res.status(400).json({error:error.message})
  res.json({data:(data||[]).reverse().map(m=>({...m,sender_name:m.sender?.full_name||m.sender?.email||'Team Member',sender_email:m.sender?.email,sender_initials:(m.sender?.full_name||m.sender?.email||'?').slice(0,2).toUpperCase()}))})
})
app.post('/api/chat/:channel', auth, async (req,res)=>{
  const channel=req.params.channel.substring(0,100), content=(req.body.content||'').trim()
  if (!content) return res.status(400).json({error:'Message content required'})
  if (content.length>5000) return res.status(400).json({error:'Message too long (max 5000 chars)'})
  const { data, error }=await supabase.from('chat_messages').insert({channel,sender_id:req.user.id,content}).select('*, sender:user_profiles!sender_id(id,full_name,email)').single()
  if (error) return res.status(400).json({error:error.message})
  const msg={...data,sender_name:data.sender?.full_name||data.sender?.email||'Team Member',sender_email:data.sender?.email,sender_initials:(data.sender?.full_name||data.sender?.email||'?').slice(0,2).toUpperCase()}
  broadcastChatMessage(msg,channel); res.json(msg)
})
app.get('/api/dm/:userId', auth, async (req,res)=>{
  const me=req.user.id, other=req.params.userId, limit=Math.min(+(req.query.limit||60),200)
  const { data, error }=await supabase.from('chat_dm_messages').select('*, sender:user_profiles!sender_id(id,full_name,email)').or(`and(sender_id.eq.${me},recipient_id.eq.${other}),and(sender_id.eq.${other},recipient_id.eq.${me})`).order('created_at',{ascending:true}).limit(limit)
  if (error) return res.status(400).json({error:error.message})
  res.json({data:(data||[]).map(m=>({...m,sender_name:m.sender?.full_name||m.sender?.email||'Member',sender_initials:(m.sender?.full_name||m.sender?.email||'?').slice(0,2).toUpperCase(),is_mine:m.sender_id===me}))})
})
app.post('/api/dm/:userId', auth, async (req,res)=>{
  const me=req.user.id, recipient=req.params.userId, content=(req.body.content||'').trim()
  if (!content) return res.status(400).json({error:'Message content required'})
  if (content.length>5000) return res.status(400).json({error:'Message too long (max 5000 chars)'})
  if (me===recipient) return res.status(400).json({error:"Can't DM yourself"})
  const { data:profile }=await supabase.from('user_profiles').select('id,full_name,email').eq('id',recipient).single()
  if (!profile) return res.status(404).json({error:'Recipient not found'})
  const { data, error }=await supabase.from('chat_dm_messages').insert({sender_id:me,recipient_id:recipient,content}).select('*, sender:user_profiles!sender_id(id,full_name,email)').single()
  if (error) return res.status(400).json({error:error.message})
  const msg={...data,sender_name:data.sender?.full_name||data.sender?.email||'Member',sender_initials:(data.sender?.full_name||data.sender?.email||'?').slice(0,2).toUpperCase(),is_mine:true,recipient_id:recipient}
  broadcastDM(msg,me,recipient); res.json(msg)
})
app.post('/api/dm/:userId/read', auth, async (req,res)=>{ const { error }=await supabase.from('chat_dm_messages').update({is_read:true}).eq('recipient_id',req.user.id).eq('sender_id',req.params.userId).eq('is_read',false); if (error) return res.status(400).json({error:error.message}); res.json({ok:true}) })

// ═══════════════════════════════════════════════════════════════════════════════
// GOOGLE DRIVE
// ═══════════════════════════════════════════════════════════════════════════════
const GOOGLE_CLIENT_ID=process.env.GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET=process.env.GOOGLE_CLIENT_SECRET
const GOOGLE_REDIRECT_URI=process.env.GOOGLE_REDIRECT_URI||'https://valor-crm.onrender.com/api/auth/google/callback'
const DRIVE_SCOPE='https://www.googleapis.com/auth/drive.file'
async function getDriveToken(userId) {
  const { data:tokenRow }=await supabase.from('user_drive_tokens').select('*').eq('user_id',userId).single()
  if (!tokenRow) return null
  if (new Date(tokenRow.expires_at)<=new Date(Date.now()+5*60*1000)) {
    const rd=await(await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:GOOGLE_CLIENT_ID,client_secret:GOOGLE_CLIENT_SECRET,refresh_token:tokenRow.refresh_token,grant_type:'refresh_token'})})).json()
    if (rd.access_token) { await supabase.from('user_drive_tokens').update({access_token:rd.access_token,expires_at:new Date(Date.now()+(rd.expires_in||3600)*1000).toISOString()}).eq('user_id',userId); return rd.access_token }
    return null
  }
  return tokenRow.access_token
}
async function driveApi(userId,endpoint,opts={}) {
  const at=await getDriveToken(userId); if (!at) throw new Error('Google Drive not connected. Please reconnect in Settings.')
  const url=endpoint.startsWith('http')?endpoint:'https://www.googleapis.com/drive/v3/'+endpoint
  const r=await fetch(url,{...opts,headers:{'Authorization':'Bearer '+at,...(opts.headers||{})}})
  if (r.status===401) { await supabase.from('user_drive_tokens').delete().eq('user_id',userId); throw new Error('Google Drive authorization expired. Please reconnect.') }
  return r
}
app.get('/api/auth/google', auth, (req,res)=>{
  if (!GOOGLE_CLIENT_ID) return res.status(503).send('GOOGLE_CLIENT_ID not configured.')
  const state=Buffer.from(JSON.stringify({userId:req.user.id,token:req.query.token})).toString('base64url')
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?'+new URLSearchParams({client_id:GOOGLE_CLIENT_ID,redirect_uri:GOOGLE_REDIRECT_URI,response_type:'code',scope:DRIVE_SCOPE+' https://www.googleapis.com/auth/userinfo.email',access_type:'offline',prompt:'consent',state}))
})
app.get('/api/auth/google/callback', async (req,res)=>{
  const { code, state, error }=req.query
  if (error) return res.redirect('/?drive_error='+encodeURIComponent(error))
  if (!code||!state) return res.redirect('/?drive_error=missing_code')
  let sd; try { sd=JSON.parse(Buffer.from(state,'base64url').toString('utf8')) } catch { return res.redirect('/?drive_error=invalid_state') }
  const td=await(await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({code,client_id:GOOGLE_CLIENT_ID,client_secret:GOOGLE_CLIENT_SECRET,redirect_uri:GOOGLE_REDIRECT_URI,grant_type:'authorization_code'})})).json()
  if (!td.access_token) return res.redirect('/?drive_error='+encodeURIComponent(td.error_description||'token_exchange_failed'))
  await supabase.from('user_drive_tokens').upsert({user_id:sd.userId,access_token:td.access_token,refresh_token:td.refresh_token||null,expires_at:new Date(Date.now()+(td.expires_in||3600)*1000).toISOString(),scope:td.scope},{onConflict:'user_id'})
  res.redirect('/?page=drive&drive_connected=1')
})
app.get('/api/drive/status', auth, async (req,res)=>{ const { data }=await supabase.from('user_drive_tokens').select('expires_at,scope').eq('user_id',req.user.id).single(); res.json({connected:!!data,expires_at:data?.expires_at}) })
app.get('/api/drive/files', auth, async (req,res)=>{
  const fid=req.query.folder_id||'root', mf=req.query.mime||null
  let query=`'${fid}' in parents and trashed=false`; if (mf) query+=` and mimeType='${mf}'`
  try { const r=await driveApi(req.user.id,`files?q=${encodeURIComponent(query)}&fields=files(id,name,mimeType,size,modifiedTime,webViewLink,owners,parents)&orderBy=folder,name&pageSize=100`,{headers:{'Content-Type':'application/json'}}); const data=await r.json(); if (!r.ok) return res.status(r.status).json({error:data.error?.message||'Drive API error'}); res.json({files:data.files||[],breadcrumb:[]}) }
  catch (e) { res.status(400).json({error:e.message}) }
})
app.post('/api/drive/upload', auth, async (req,res)=>{
  if (!memUpload) return res.status(503).json({error:'File upload not available. Run: npm install multer'})
  memUpload.single('file')(req,res,async (err)=>{
    if (err) return res.status(400).json({error:err.message})
    const { folder_id='root' }=req.body, file=req.file
    if (!file) return res.status(400).json({error:'No file provided'})
    const boundary='valorcrmboundary'+Date.now(), meta=JSON.stringify({name:file.originalname,parents:[folder_id]})
    const partHead=Buffer.from('--'+boundary+'\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'+meta+'\r\n--'+boundary+'\r\nContent-Type: '+file.mimetype+'\r\n\r\n','utf8')
    const partTail=Buffer.from('\r\n--'+boundary+'--','utf8'), uploadBody=Buffer.concat([partHead,file.buffer,partTail])
    try {
      const at=await getDriveToken(req.user.id); if (!at) return res.status(403).json({error:'Google Drive not connected'})
      const r=await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink',{method:'POST',headers:{'Authorization':'Bearer '+at,'Content-Type':'multipart/related; boundary='+boundary},body:uploadBody})
      const data=await r.json(); if (!r.ok) return res.status(r.status).json({error:data.error?.message||'Upload failed'})
      try { await safeInsertLog({user_id:req.user.id,action:'DRIVE_UPLOAD',details:'Uploaded: '+file.originalname}) } catch (_) {}; res.json({file:data})
    } catch (e) { res.status(500).json({error:e.message}) }
  })
})
app.get('/api/drive/download/:fileId', auth, async (req,res)=>{
  try {
    const mr=await driveApi(req.user.id,`files/${req.params.fileId}?fields=name,mimeType,size`), meta=await mr.json()
    if (!mr.ok) return res.status(mr.status).json({error:meta.error?.message})
    const fr=await driveApi(req.user.id,`files/${req.params.fileId}?alt=media`); if (!fr.ok) return res.status(fr.status).json({error:'Download failed'})
    res.setHeader('Content-Type',meta.mimeType||'application/octet-stream'); res.setHeader('Content-Disposition',`attachment; filename="${(meta.name||'file').replace(/"/g,'')}"`)
    const { Readable }=require('stream'); Readable.fromWeb(fr.body).pipe(res)
  } catch (e) { res.status(500).json({error:e.message}) }
})
app.post('/api/drive/folder', auth, async (req,res)=>{
  const { name, parent_id='root' }=req.body; if (!name?.trim()) return res.status(400).json({error:'Folder name required'})
  try { const r=await driveApi(req.user.id,'files?fields=id,name,webViewLink',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name.trim(),mimeType:'application/vnd.google-apps.folder',parents:[parent_id]})}); const data=await r.json(); if (!r.ok) return res.status(r.status).json({error:data.error?.message}); res.json({folder:data}) }
  catch (e) { res.status(500).json({error:e.message}) }
})
app.delete('/api/drive/files/:fileId', auth, async (req,res)=>{
  try { const r=await driveApi(req.user.id,`files/${req.params.fileId}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({trashed:true})}); if (!r.ok) { const d=await r.json(); return res.status(r.status).json({error:d.error?.message||'Delete failed'}) }; res.json({success:true}) }
  catch (e) { res.status(500).json({error:e.message}) }
})
app.post('/api/drive/export', auth, async (req,res)=>{
  const { type, file_name='valor-export.csv', folder_id='root' }=req.body
  const config=EXPORT_CONFIG[type]; if (!config) return res.status(400).json({error:'Unknown export type: '+type})
  const csvRows=[config.headers.map(esc).join(',')]; let offset=0
  while (true) { const { data, error }=await supabase.from(config.table).select(config.select).order(config.order.col,{ascending:config.order.asc}).range(offset,offset+PAGE_SIZE-1); if (error||!data?.length) break; data.forEach(r=>csvRows.push(config.map(r).map(esc).join(','))); offset+=PAGE_SIZE; if (data.length<PAGE_SIZE) break }
  try {
    const at=await getDriveToken(req.user.id); if (!at) return res.status(403).json({error:'Google Drive not connected'})
    const boundary='valorexportboundary'+Date.now(), meta=JSON.stringify({name:file_name,parents:[folder_id],mimeType:'text/csv'})
    const bodyStr=['--'+boundary,'Content-Type: application/json; charset=UTF-8','',meta,'--'+boundary,'Content-Type: text/csv','',csvRows.join('\n'),'--'+boundary+'--'].join('\r\n')
    const r=await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,webViewLink',{method:'POST',headers:{'Authorization':'Bearer '+at,'Content-Type':'multipart/related; boundary='+boundary},body:bodyStr})
    const data=await r.json(); if (!r.ok) return res.status(r.status).json({error:data.error?.message||'Drive upload failed'})
    try { await safeInsertLog({user_id:req.user.id,action:'DRIVE_EXPORT',details:`Exported ${type} to Drive: ${file_name}`}) } catch (_) {}; res.json({file:data,drive_link:data.webViewLink})
  } catch (e) { res.status(500).json({error:e.message}) }
})

// ─── TERRITORIES ──────────────────────────────────────────────────────────────
app.get('/api/territories', auth, async (req,res)=>{ const { data, error }=await supabase.from('territories').select('*').order('name',{ascending:true}); if (error) return res.status(400).json({error:error.message}); res.json({data}) })
app.post('/api/territories', auth, requireAdmin, async (req,res)=>{
  const { name, states, description }=req.body; if (!name?.trim()) return res.status(400).json({error:'Territory name required'})
  const { data, error }=await supabase.from('territories').insert({name:name.trim(),states:states||[],description:description||''}).select().single()
  if (error) return res.status(400).json({error:error.message})
  try { await safeInsertLog({user_id:req.user.id,action:'CREATE_TERRITORY',details:`Created territory: ${name}`}) } catch (_) {}; res.json(data)
})
app.put('/api/territories/:id', auth, requireAdmin, async (req,res)=>{
  const body=Object.fromEntries(Object.entries(req.body).filter(([k])=>['name','states','description'].includes(k)))
  const { data, error }=await supabase.from('territories').update(body).eq('id',req.params.id).select().single()
  if (error) return res.status(400).json({error:error.message}); res.json(data)
})
app.delete('/api/territories/:id', auth, requireAdmin, async (req,res)=>{ const { error }=await supabase.from('territories').delete().eq('id',req.params.id); if (error) return res.status(400).json({error:error.message}); res.json({success:true}) })
app.get('/api/users/:id/territories', auth, requireAdmin, async (req,res)=>{ const { data, error }=await supabase.from('user_territory_assignments').select('territory_id, territories(id,name,states,description)').eq('user_id',req.params.id); if (error) return res.status(400).json({error:error.message}); res.json({data:(data||[]).map(r=>r.territories)}) })
app.put('/api/users/:id/territories', auth, requireAdmin, async (req,res)=>{
  const { territory_ids=[] }=req.body; if (!Array.isArray(territory_ids)) return res.status(400).json({error:'territory_ids must be an array'})
  const { error:delErr }=await supabase.from('user_territory_assignments').delete().eq('user_id',req.params.id); if (delErr) return res.status(400).json({error:delErr.message})
  if (territory_ids.length>0) { const rows=territory_ids.map(tid=>({user_id:req.params.id,territory_id:tid,assigned_by:req.user.id})); const { error:insErr }=await supabase.from('user_territory_assignments').insert(rows); if (insErr) return res.status(400).json({error:insErr.message}) }
  await supabase.from('user_profiles').update({territory_id:territory_ids[0]||null}).eq('id',req.params.id)
  try { const tRes=territory_ids.length?await supabase.from('territories').select('name').in('id',territory_ids):{data:[]}; const tNames=(tRes.data||[]).map(t=>t.name).join(', ')||'none'; await safeInsertLog({user_id:req.user.id,action:'ASSIGN_TERRITORIES',record_type:'user_profiles',record_id:req.params.id,details:`Assigned territories: ${tNames}`}) } catch (_) {}
  res.json({success:true,territory_ids})
})
app.get('/api/me/wib-view', auth, async (req,res)=>{
  const [{ data:pref },{ data:assignments }]=await Promise.all([supabase.from('user_wib_view_prefs').select('view_mode').eq('user_id',req.user.id).single(),supabase.from('user_territory_assignments').select('territory_id, territories(id,name)').eq('user_id',req.user.id)])
  res.json({view_mode:pref?.view_mode||'all',territories:(assignments||[]).map(a=>a.territories).filter(Boolean)})
})
app.put('/api/me/wib-view', auth, async (req,res)=>{
  const { view_mode }=req.body; if (!['all','my_territories'].includes(view_mode)) return res.status(400).json({error:'view_mode must be "all" or "my_territories"'})
  const { error }=await supabase.from('user_wib_view_prefs').upsert({user_id:req.user.id,view_mode,updated_at:new Date().toISOString()},{onConflict:'user_id'}); if (error) return res.status(400).json({error:error.message}); res.json({success:true,view_mode})
})
app.get('/api/wibs/my', auth, async (req,res)=>{
  const { search, limit=1000 }=req.query
  const { data:assignments }=await supabase.from('user_territory_assignments').select('territory_id').eq('user_id',req.user.id)
  const tids=(assignments||[]).map(a=>a.territory_id)
  let q=supabase.from('wib_records').select('*, owner:user_profiles!owner_id(full_name,email)',{count:'exact'}).limit(Number(limit))
  if (tids.length>0) q=q.in('territory_id',tids); if (search) q=q.ilike('wib_name',`%${search}%`)
  const { data, error, count }=await q; if (error) return res.status(400).json({error:error.message}); res.json({data,count})
})
app.put('/api/users/:id/territory', auth, requireAdmin, async (req,res)=>{ const { territory_id }=req.body; const { data, error }=await supabase.from('user_profiles').update({territory_id:territory_id||null}).eq('id',req.params.id).select('id,email,full_name,role,territory_id').single(); if (error) return res.status(400).json({error:error.message}); res.json(data) })
app.put('/api/wibs/:id/territory', auth, requireAdmin, async (req,res)=>{ const { territory_id }=req.body; const { data, error }=await supabase.from('wib_records').update({territory_id:territory_id||null}).eq('id',req.params.id).select().single(); if (error) return res.status(400).json({error:error.message}); res.json(data) })

// ─── SERVE FRONTEND ───────────────────────────────────────────────────────────
let _htmlPath=null
function findHtmlPath() {
  if (_htmlPath&&fs.existsSync(_htmlPath)) return _htmlPath
  for (const p of [path.join(__dirname,'public','index.html'),path.join(__dirname,'index.html')]) if (fs.existsSync(p)) { _htmlPath=p; return p }
  return null
}
app.get('*', (req,res)=>{
  if (req.path.startsWith('/api/')) return res.status(404).json({error:'Not found'})
  const htmlPath=findHtmlPath()
  if (htmlPath) { res.setHeader('Content-Type','text/html; charset=utf-8'); res.setHeader('X-Content-Type-Options','nosniff'); res.setHeader('Cache-Control','no-cache'); return res.sendFile(htmlPath) }
  res.status(503).send('<!DOCTYPE html><html><head><title>Valor CRM</title></head><body style="font-family:sans-serif;background:#0B1E3C;color:#fff;padding:40px;text-align:center"><h2>Valor CRM</h2><h3 style="color:#C9A84C">Deployment Issue</h3><p>index.html not found. Upload both server.js and index.html to GitHub, then wait ~60s for Render to redeploy.</p></body></html>')
})

// ─── SERVER START ─────────────────────────────────────────────────────────────
const PORT=process.env.PORT||3001
app.listen(PORT, ()=>{
  console.log(`✅ Valor CRM on port ${PORT}`)
  console.log(`   SUPABASE_URL:         ${SUPABASE_URL?'SET ✓':'MISSING ✗'}`)
  console.log(`   SUPABASE_ANON_KEY:    ${SUPABASE_ANON_KEY?'SET ✓':'MISSING — login may fail'}`)
  console.log(`   SUPABASE_SERVICE_KEY: ${SUPABASE_SERVICE_KEY?'SET ✓':'MISSING ✗'}`)
  console.log('')
  console.log('   💬 LIVE CHAT: SSE stream + DMs enabled')
  console.log('   📂 DRIVE UPLOAD: multer memoryStorage — 50MB (multipart/related)')
  console.log('   📊 EXPORT: streaming paginated CSV, PAGE_SIZE=1000')
  console.log('   📥 IMPORT: lightweight JWT auth — multi-batch safe')
  console.log('   🧹 PURGE: GET /api/admin/purge-broken-imports (admin only)')
  console.log('')
  console.log("   CREATE TABLE IF NOT EXISTS role_permissions (id INTEGER PRIMARY KEY DEFAULT 1, permissions JSONB NOT NULL DEFAULT '{}', updated_at TIMESTAMPTZ DEFAULT NOW());")
  console.log('   ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;')
  console.log('   CREATE POLICY "Service role full access" ON role_permissions USING (true) WITH CHECK (true);')
})
