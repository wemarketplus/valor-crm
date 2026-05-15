const express = require('express')
const { createClient } = require('@supabase/supabase-js')
const path = require('path')
const fs = require('fs')
const app = express()

// ─── SECURITY HEADERS ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('X-XSS-Protection', '1; mode=block')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.removeHeader('X-Powered-By')
  const origin = req.headers.origin
  const allowed = ['https://valor-crm.onrender.com','http://localhost:3001','http://localhost:3000']
  if (origin && allowed.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin)
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  if (req.method === 'OPTIONS') return res.sendStatus(200)
  next()
})

app.use(express.json({ limit: '50mb' }))

// ─── RATE LIMITING ─────────────────────────────────────────────────────────────
const loginAttempts = new Map()
function rateLimitLogin(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'
  const now = Date.now(), window = 15 * 60 * 1000, max = 10
  const e = loginAttempts.get(ip) || { count: 0, resetAt: now + window }
  if (now > e.resetAt) { e.count = 0; e.resetAt = now + window }
  e.count++
  loginAttempts.set(ip, e)
  if (e.count > max) {
    const mins = Math.ceil((e.resetAt - now) / 60000)
    return res.status(429).json({ error: `Too many login attempts. Try again in ${mins} minutes.` })
  }
  next()
}
setInterval(() => { const now = Date.now(); for (const [ip, e] of loginAttempts) if (now > e.resetAt) loginAttempts.delete(ip) }, 30 * 60 * 1000)

// ─── SUPABASE CLIENTS ──────────────────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.error('FATAL: Missing SUPABASE_URL or SUPABASE_SERVICE_KEY')
  process.exit(1)
}

// Service client — for DB queries and admin ops (bypasses RLS)
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

// Auth client — for signInWithPassword (uses anon key, falls back to service key)
// IMPORTANT: No custom auth options — they break signInWithPassword session return
const authClient = SUPABASE_ANON_KEY
  ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY)
  : createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)

console.log(`Auth client using: ${SUPABASE_ANON_KEY ? 'ANON KEY ✓' : 'SERVICE KEY (set SUPABASE_ANON_KEY for best results)'}`)

// ─── BLOCK SOURCE FILE EXPOSURE ────────────────────────────────────────────────
const BLOCKED = ['.js','.ts','.json','.env','.md','.lock','.sh','.sql']
app.use((req, res, next) => {
  const p = req.path.toLowerCase()
  if (p.startsWith('/api/')) return next()
  if (p === '/' || p === '/index.html' || p === '/favicon.ico') return next()
  if (BLOCKED.some(ext => p.endsWith(ext))) return res.status(404).send('Not found')
  next()
})

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), { index: false, dotfiles: 'deny' }))
app.use(express.static(path.join(__dirname), { index: false, dotfiles: 'deny' }))

// ─── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
async function auth(req, res, next) {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '').trim()
    if (!token || token.length < 10) return res.status(401).json({ error: 'Authentication required' })
    const { data: { user }, error } = await authClient.auth.getUser(token)
    if (error || !user) return res.status(401).json({ error: 'Session expired. Please sign in again.' })
    const { data: profile, error: pe } = await supabase.from('user_profiles').select('*').eq('id', user.id).single()
    if (pe || !profile) return res.status(401).json({ error: 'User profile not found. Contact administrator.' })
    if (profile.is_active === false) return res.status(403).json({ error: 'Account disabled. Contact your administrator.' })
    req.user = profile
    next()
  } catch (err) {
    console.error('Auth middleware error:', err.message)
    return res.status(500).json({ error: 'Authentication service error' })
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
    const { new_password } = req.body
    if (!new_password || new_password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' })
    const { data: target } = await supabase.from('user_profiles').select('email').eq('id', req.params.id).single()
    if (!target) return res.status(404).json({ error: 'User not found' })
    const { error } = await supabase.auth.admin.updateUserById(req.params.id, { password: new_password })
    if (error) return res.status(400).json({ error: error.message })
    try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'RESET_PASSWORD', details: `Admin reset password for: ${target.email}` }) } catch(_) {}
    res.json({ success: true, message: `Password reset for ${target.email}` })
  } catch (err) {
    res.status(500).json({ error: 'Password reset failed. Please try again.' })
  }
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
  const allowed = ['wib_name','short_name','state','status','wib_phone','wib_email','website','max_award_per_ein','match_requirement_pct','wib_type','source_url','google_drive_folder_url','next_steps','blockers','notes','iwt_program_active','independent_creation_logged','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.wib_name?.trim()) return res.status(400).json({ error: 'WIB name required' })
  if (!body.source_url?.trim()) return res.status(400).json({ error: 'Source URL required (public government page)' })
  const { data, error } = await supabase.from('wib_records').insert({ ...body, owner_id: req.user.id }).select('*, owner:user_profiles!owner_id(full_name,email)').single()
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CREATE_WIB', record_type: 'wib_records', record_id: data.id, details: `Created: ${data.wib_name}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/wibs/:id', auth, async (req, res) => {
  const allowed = ['wib_name','short_name','state','status','wib_phone','wib_email','website','max_award_per_ein','match_requirement_pct','wib_type','source_url','google_drive_folder_url','next_steps','blockers','notes','iwt_program_active','independent_creation_logged','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('wib_records').update(body).eq('id', req.params.id).select('*, owner:user_profiles!owner_id(full_name,email)').single()
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'UPDATE_WIB', record_type: 'wib_records', record_id: req.params.id, details: `Updated: ${data.wib_name}` }) } catch(_) {}
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
  const allowed = ['company_name','company_type','status','fein','domain','employee_count_total','avg_hourly_wage','primary_contact_name','primary_contact_email','primary_contact_phone','training_needs','notes','rating']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.company_name?.trim()) return res.status(400).json({ error: 'Company name required' })
  const { data, error } = await supabase.from('companies').insert(body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CREATE_COMPANY', record_type: 'companies', record_id: data.id, details: `Created: ${data.company_name}` }) } catch(_) {}
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
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CREATE_FUNDING', record_type: 'funding_opportunities', record_id: data.id, details: `Created: ${data.opportunity_name}` }) } catch(_) {}
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
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'CREATE_APPLICATION', record_type: 'applications', record_id: data.id, details: `Created: ${data.application_number}` }) } catch(_) {}
  res.json(data)
})

app.put('/api/applications/:id', auth, async (req, res) => {
  const allowed = ['status','award_amount_requested','award_amount_approved','submission_date','decision_date','notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('applications').update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'UPDATE_APPLICATION', record_type: 'applications', record_id: req.params.id, details: `Status: ${body.status || 'updated'}` }) } catch(_) {}
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
  try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'UPDATE_REVENUE', record_type: 'revenue_records', record_id: req.params.id, details: `Invoice: ${body.invoice_status || 'updated'}` }) } catch(_) {}
  res.json(data)
})

// ─── NOTES ────────────────────────────────────────────────────────────────────
app.get('/api/notes', auth, async (req, res) => {
  const { record_type, record_id, limit = 50 } = req.query
  let q = supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name,email)').eq('action', 'NOTE')
  if (record_type) q = q.eq('record_type', record_type)
  if (record_id) q = q.eq('record_id', record_id)
  q = q.order('created_at', { ascending: false }).limit(Math.min(+limit, 100))
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.post('/api/notes', auth, async (req, res) => {
  const { record_type, record_id, content, note_type = 'Note', is_aircall = false } = req.body
  if (!content?.trim()) return res.status(400).json({ error: 'Note content required' })
  const { data, error } = await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'NOTE', record_type, record_id,
    details: content.trim(), metadata: { note_type, is_aircall }
  }).select('*, user:user_profiles!user_id(full_name,email)').single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── TASKS ────────────────────────────────────────────────────────────────────
app.get('/api/tasks', auth, async (req, res) => {
  const { record_id, limit = 100 } = req.query
  let q = supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name)').eq('action', 'TASK')
  if (record_id) q = q.eq('record_id', record_id)
  q = q.order('created_at', { ascending: false }).limit(Math.min(+limit, 100))
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.post('/api/tasks', auth, async (req, res) => {
  const { title, due_date, record_type, record_id, priority = 'normal', notes, assigned_to } = req.body
  if (!title?.trim()) return res.status(400).json({ error: 'Task title required' })
  const { data, error } = await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'TASK', record_type, record_id,
    details: title.trim(),
    metadata: { due_date, priority, notes, done: false, assigned_to, created_by: req.user.full_name || req.user.email }
  }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.put('/api/tasks/:id', auth, async (req, res) => {
  const { data: existing } = await supabase.from('activity_log').select('metadata').eq('id', req.params.id).single()
  const { data, error } = await supabase.from('activity_log').update({ metadata: { ...(existing?.metadata || {}), ...req.body } }).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── ACTIVITY / AUDIT ─────────────────────────────────────────────────────────
app.get('/api/activity', auth, async (req, res) => {
  const { record_type, record_id, limit = 100 } = req.query
  let q = supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name,email)').neq('action', 'NOTE').neq('action', 'TASK')
  if (record_type) q = q.eq('record_type', record_type)
  if (record_id) q = q.eq('record_id', record_id)
  q = q.order('created_at', { ascending: false }).limit(Math.min(+limit, 200))
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.get('/api/audit', auth, requireAdmin, async (req, res) => {
  const { limit = 100, offset = 0 } = req.query
  const { data, error, count } = await supabase.from('activity_log').select('*, user:user_profiles!user_id(full_name,email)', { count: 'exact' }).order('created_at', { ascending: false }).range(+offset, +offset + Math.min(+limit, 200) - 1)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

// ─── USERS ────────────────────────────────────────────────────────────────────
app.get('/api/users', auth, requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('user_profiles').select('id,email,full_name,role,title,phone,is_active,created_at,last_login_at').order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
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
    try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'UPDATE_USER', details: `Updated: ${data.email}${is_active === false ? ' — DISABLED' : ''}` }) } catch(_) {}
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
  const { data: existing } = await supabase.from('activity_log').select('metadata').eq('id', req.params.id).single()
  const merged = { ...(existing?.metadata || {}), ...{ name, title, email, phone, notes } }
  const { data, error } = await supabase.from('activity_log').update({ details: name || existing?.metadata?.name, metadata: merged }).eq('id', req.params.id).select().single()
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
  const { data: existing } = await supabase.from('activity_log').select('metadata,details').eq('id', req.params.id).single()
  const merged = { ...(existing?.metadata || {}), ...req.body }
  const { data, error } = await supabase.from('activity_log').update({ details: req.body.name || existing?.details, metadata: merged }).eq('id', req.params.id).select().single()
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
  const { data: existing } = await supabase.from('activity_log').select('metadata').eq('id', req.params.id).single()
  const merged = { ...(existing?.metadata || {}), ...req.body }
  const { data, error } = await supabase.from('activity_log').update({ metadata: merged }).eq('id', req.params.id).select().single()
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
  const { data: existing } = await supabase.from('activity_log').select('metadata').eq('id', req.params.id).single()
  const merged = { ...(existing?.metadata || {}), ...req.body }
  const { data, error } = await supabase.from('activity_log').update({ metadata: merged }).eq('id', req.params.id).select().single()
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
      const valid = [], skipped = []
      for (const row of rows) {
        if (!row['WIB Name']?.trim()) { skipped.push('Skipped — WIB Name required'); continue }
        valid.push({
          wib_name: row['WIB Name'].trim(),
          short_name: row['Short Name'] || null,
          state: row['State'] || null,
          status: (() => {
            const rawS = (row['Status'] || '').toLowerCase().trim()
            const m = {
              'funding available':'funding_available','funding_available':'funding_available','active':'funding_available','open':'funding_available',
              'follow up needed':'follow_up_needed','follow_up_needed':'follow_up_needed','follow up':'follow_up_needed',
              'pending employer':'pending_employer','pending_employer':'pending_employer','pending':'pending_employer',
              'no reachout':'no_reachout_complete','no_reachout_complete':'no_reachout_complete','new':'no_reachout_complete',
              'funding not available':'funding_not_available','funding_not_available':'funding_not_available','closed':'funding_not_available',
              'stop applications':'stop_applications','stop_applications':'stop_applications',
            }
            return m[rawS] || 'no_reachout_complete'
          })(),
          wib_phone: row['Phone'] || null,
          wib_email: row['Email'] || null,
          website: row['Website'] || null,
          source_url: row['Source URL'] || row['WIB Name'], // fallback if no URL
          max_award_per_ein: row['Max Award'] ? parseFloat(row['Max Award']) : null,
          match_requirement_pct: row['Match %'] ? parseFloat(row['Match %']) : null,
          iwt_program_active: (row['IWT Active'] || '').toLowerCase() === 'yes',
          owner_id: req.user.id,
          independent_creation_logged: true,
          last_verified_date: today
        })
      }
      results.errors.push(...skipped)
      // Bulk insert in chunks of 500
      for (let i = 0; i < valid.length; i += 500) await bulkInsert('wib_records', valid.slice(i, i + 500))

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

        const { error: insertErr } = await supabase.from('companies').insert(insertRow)
        if (insertErr) {
          results.errors.push(`"${name}": ${insertErr.message}`)
          if (results.errors.length === 1) {
            console.error('First company import error:', insertErr.code, insertErr.message)
            console.error('Hint:', insertErr.hint, '| Details:', insertErr.details)
            console.error('Row attempted:', JSON.stringify(insertRow))
          }
        } else {
          results.created++
        }
      }

    } else if (type === 'locations') {
      const valid = []
      for (const row of rows) {
        const name = row['Location Name']?.trim()
        if (!name) { results.errors.push('Skipped row — Location Name required'); continue }
        valid.push({
          location_name: name,
          state: row['State'] || null,
          county: row['County'] || null,
          city: row['City'] || null,
          status: (() => {
            const rawS = (row['Status'] || '').toLowerCase().trim()
            // Locations valid: prospect, active, inactive (text field, less strict)
            return rawS || 'prospect'
          })(),
          employee_count: row['Employee Count'] ? parseInt(row['Employee Count']) : null
        })
      }
      for (let i = 0; i < valid.length; i += 500) await bulkInsert('locations', valid.slice(i, i + 500))

    } else if (type === 'funding') {
      const valid = []
      for (const row of rows) {
        const name = row['Opportunity Name']?.trim()
        if (!name) { results.errors.push('Skipped row — Opportunity Name required'); continue }
        valid.push({
          opportunity_name: name,
          status: (() => {
            const rawS = (row['Status'] || '').toLowerCase().trim()
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
          program_type: row['Program Type'] || null,
          source_url: row['Source URL'] || name,
          max_award_per_ein: row['Max Award/EIN'] ? parseFloat(row['Max Award/EIN']) : null,
          application_deadline: row['Deadline'] || null,
          independent_creation_logged: true
        })
      }
      for (let i = 0; i < valid.length; i += 500) await bulkInsert('funding_opportunities', valid.slice(i, i + 500))

    } else if (type === 'applications') {
      const valid = []
      for (const row of rows) {
        // Look up company and WIB by name to get their IDs
        const companyName = row['Company']?.trim() || row['Company Name']?.trim() || row['Employer']?.trim() || row['Record']?.trim()
        const wibName = row['WIB']?.trim() || row['Workforce Board']?.trim() || row['WIB Name']?.trim()
        if (!companyName) { results.errors.push('Skipped row — Company name required'); continue }

        // Find company ID
        let company_id = null
        if (companyName) {
          const { data: cos } = await supabase.from('companies').select('id').ilike('company_name', `%${companyName}%`).limit(1)
          company_id = cos?.[0]?.id || null
        }
        // Find WIB ID
        let wib_id = null
        if (wibName) {
          const { data: wibs } = await supabase.from('wib_records').select('id').ilike('wib_name', `%${wibName}%`).limit(1)
          wib_id = wibs?.[0]?.id || null
        }

        if (!company_id) { results.errors.push(`Skipped "${companyName}" — company not found in system (add it first)`); continue }

        const rawStatus = (row['Status'] || row['Stage'] || 'intake').toLowerCase()
        const statusMap = {
          'intake': 'intake', 'in progress': 'in_progress', 'in_progress': 'in_progress',
          'submitted': 'submitted', 'under review': 'under_review', 'under_review': 'under_review',
          'awarded': 'awarded', 'denied': 'denied', 'withdrawn': 'withdrawn', 'active': 'active',
        }
        const status = statusMap[rawStatus] || 'intake'

        valid.push({
          company_id,
          wib_id,
          status,
          award_amount_requested: (() => { const v = row['Award Requested'] || row['Amount Requested'] || row['Requested']; return v ? parseFloat(String(v).replace(/[$,]/g,'')) : null })(),
          award_amount_approved: (() => { const v = row['Award Approved'] || row['Amount Approved'] || row['Approved']; return v ? parseFloat(String(v).replace(/[$,]/g,'')) : null })(),
          submission_date: row['Submission Date'] || row['Submitted'] || null,
          decision_date: row['Decision Date'] || row['Decision'] || null,
          notes: row['Notes'] || row['Description'] || null,
          owner_id: req.user.id,
        })
      }
      // Applications must be inserted one at a time (triggers auto-number generation)
      for (const app of valid) {
        const { error } = await supabase.from('applications').insert(app)
        if (error) results.errors.push(`Insert error: ${error.message}`)
        else results.created++
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
    try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'UPDATE_PERMISSIONS', details: `Set ${permission}/${role} = ${value}` }) } catch(_) {}
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
const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`
app.get('/api/export/:type', auth, async (req, res) => {
  const { type } = req.params
  let rows = [], headers = []
  const filename = `valor-${type}-${new Date().toISOString().split('T')[0]}.csv`
  try {
    if (type === 'wibs') {
      const { data } = await supabase.from('wib_records').select('wib_name,short_name,state,status,wib_phone,wib_email,website,max_award_per_ein,match_requirement_pct,iwt_program_active,source_url,call_priority_score,last_verified_date,next_steps,blockers').order('call_priority_score', { ascending: false })
      headers = ['WIB Name','Short Name','State','Status','Phone','Email','Website','Max Award/EIN','Match %','IWT Active','Source URL','Score','Last Verified','Next Steps','Blockers']
      rows = (data || []).map(r => [r.wib_name,r.short_name||'',r.state,r.status,r.wib_phone||'',r.wib_email||'',r.website||'',r.max_award_per_ein||'',r.match_requirement_pct||'',r.iwt_program_active?'Yes':'No',r.source_url||'',r.call_priority_score||0,r.last_verified_date||'',r.next_steps||'',r.blockers||''])
    } else if (type === 'companies') {
      const { data } = await supabase.from('companies').select('company_name,company_type,status,fein,domain,employee_count_total,avg_hourly_wage,primary_contact_name,primary_contact_email,primary_contact_phone,training_needs,notes,rating,created_at').order('company_name')
      headers = ['Company Name','Type','Status','FEIN','Domain','Employees','Avg Hourly Wage','Contact Name','Contact Email','Contact Phone','Training Needs','Notes','Rating','Created']
      rows = (data || []).map(r => [r.company_name,r.company_type||'',r.status,r.fein||'',r.domain||'',r.employee_count_total||'',r.avg_hourly_wage||'',r.primary_contact_name||'',r.primary_contact_email||'',r.primary_contact_phone||'',r.training_needs||'',r.notes||'',r.rating||'',r.created_at?.split('T')[0]||''])
    } else if (type === 'applications') {
      const { data } = await supabase.from('applications').select('application_number,status,award_amount_requested,award_amount_approved,submission_date,created_at').order('created_at', { ascending: false })
      headers = ['App Number','Status','Requested','Approved','Submitted','Created']
      rows = (data || []).map(r => [r.application_number,r.status,r.award_amount_requested||'',r.award_amount_approved||'',r.submission_date||'',r.created_at?.split('T')[0]||''])
    } else if (type === 'funding') {
      const { data } = await supabase.from('funding_opportunities').select('opportunity_name,status,program_type,max_award_per_ein,application_deadline,source_url,created_at')
      headers = ['Opportunity','Status','Program','Max Award','Deadline','Source URL','Created']
      rows = (data || []).map(r => [r.opportunity_name,r.status,r.program_type||'',r.max_award_per_ein||'',r.application_deadline||'',r.source_url||'',r.created_at?.split('T')[0]||''])
    } else if (type === 'revenue') {
      const { data } = await supabase.from('revenue_records').select('fee_model,grant_award_amount,calculated_success_fee,invoice_status,payment_received_date,created_at')
      headers = ['Fee Model','Grant Award','Valor Fee','Invoice Status','Payment Date','Created']
      rows = (data || []).map(r => [r.fee_model||'',r.grant_award_amount||'',r.calculated_success_fee||'',r.invoice_status||'',r.payment_received_date||'',r.created_at?.split('T')[0]||''])
    } else if (type === 'users') {
      if (!['super_admin','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' })
      const { data } = await supabase.from('user_profiles').select('full_name,email,role,title,is_active,created_at')
      headers = ['Name','Email','Role','Title','Active','Created']
      rows = (data || []).map(r => [r.full_name||'',r.email,r.role,r.title||'',r.is_active?'Yes':'No',r.created_at?.split('T')[0]||''])
    } else if (type === 'locations') {
      const { data } = await supabase.from('locations').select('location_name,state,county,city,status,employee_count,created_at').order('location_name')
      headers = ['Location','State','County','City','Status','Employees','Created']
      rows = (data || []).map(r => [r.location_name,r.state||'',r.county||'',r.city||'',r.status||'',r.employee_count||'',r.created_at?.split('T')[0]||''])
    } else if (type === 'compliance') {
      const { data } = await supabase.from('v_compliance_alerts').select('*').order('days_until_final_due')
      headers = ['Application #','Company','WIB','Status','Award Amount','Training End','Final Report Due','Days Until Due','Report Submitted','Attendance Collected','Notes']
      rows = (data || []).map(r => [r.application_number||'',r.company_name||'',r.wib_name||'',r.status||'',r.award_amount_approved||'',r.training_end_date||'',r.final_report_due_date||'',r.days_until_final_due??'',r.final_report_submitted?'Yes':'No',r.attendance_sheets_collected?'Yes':'No',r.compliance_notes||''])
    } else if (type === 'audit') {
      if (!['super_admin','admin'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' })
      const { data } = await supabase.from('activity_log').select('action,details,record_type,created_at,user:user_profiles!user_id(email)').order('created_at', { ascending: false }).limit(1000)
      headers = ['Action','User','Details','Record Type','Timestamp']
      rows = (data || []).map(r => [r.action,r.user?.email||'',r.details||'',r.record_type||'',r.created_at||''])
    } else {
      return res.status(400).json({ error: 'Unknown export type' })
    }
    try { await supabase.from('activity_log').insert({ user_id: req.user.id, action: 'EXPORT', details: `Exported ${type} (${rows.length} records)` }) } catch(_) {}
    const csv = [headers.map(esc).join(','), ...rows.map(r => r.map(esc).join(','))].join('\n')
    res.setHeader('Content-Type', 'text/csv')
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)
    res.send(csv)
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.get('/api/template/:type', auth, (req, res) => {
  const templates = {
    wibs: 'WIB Name,Short Name,State,Status,Phone,Email,Website,Max Award,Match %,IWT Active,Source URL',
    companies: 'Company Name,Type,Status,FEIN,Domain,Employee Count,Avg Wage,Contact Name,Contact Email',
    locations: 'Location Name,State,County,City,Status,Employee Count',
    funding: 'Opportunity Name,Status,Program Type,Max Award/EIN,Deadline,Source URL',
  }
  const csv = templates[req.params.type]
  if (!csv) return res.status(400).json({ error: 'Unknown template' })
  res.setHeader('Content-Type', 'text/csv')
  res.setHeader('Content-Disposition', `attachment; filename="valor-${req.params.type}-template.csv"`)
  res.send(csv)
})

// ─── SERVE FRONTEND ───────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  const candidates = [
    path.join(__dirname, 'public', 'index.html'),
    path.join(__dirname, 'index.html'),
  ]
  for (const htmlPath of candidates) {
    if (fs.existsSync(htmlPath)) {
      res.setHeader('X-Content-Type-Options', 'nosniff')
      return res.sendFile(htmlPath)
    }
  }
  res.status(503).send(`<html><body style="font-family:sans-serif;padding:40px;text-align:center"><h2>🛡️ Valor CRM</h2><p>Platform loading. Please try again in 60 seconds.</p><p style="color:#999;font-size:12px">If this persists, check deployment logs on Render.</p></body></html>`)
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
