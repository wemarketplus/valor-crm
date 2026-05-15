const express = require('express')
const { createClient } = require('@supabase/supabase-js')
const path = require('path')
const fs = require('fs')
const app = express()

// ─── SECURITY HEADERS ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('X-XSS-Protection', '1; mode=block')
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
  res.removeHeader('X-Powered-By')
  const origin = req.headers.origin
  const allowed = [
    'https://valor-crm.onrender.com',
    'http://localhost:3001',
    'http://localhost:3000'
  ]
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin)
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization')
  if (req.method === 'OPTIONS') return res.sendStatus(200)
  next()
})

app.use(express.json({ limit: '2mb' }))

// ─── RATE LIMITING ─────────────────────────────────────────────────────────────
const loginAttempts = new Map()
function rateLimitLogin(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'
  const now = Date.now()
  const window = 15 * 60 * 1000 // 15 min
  const max = 8
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
// Clean up stale rate limit entries every 30 min
setInterval(() => {
  const now = Date.now()
  for (const [ip, e] of loginAttempts) {
    if (now > e.resetAt) loginAttempts.delete(ip)
  }
}, 30 * 60 * 1000)

// ─── SUPABASE ──────────────────────────────────────────────────────────────────
const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY

if (!SUPABASE_URL) { console.error('FATAL: Missing SUPABASE_URL'); process.exit(1) }
if (!SUPABASE_SERVICE_KEY) { console.error('FATAL: Missing SUPABASE_SERVICE_KEY'); process.exit(1) }
if (!SUPABASE_ANON_KEY) { console.warn('WARNING: No SUPABASE_ANON_KEY — using service key for auth (set this!)') }

// authClient: ANON KEY for signInWithPassword — correct for user-facing auth
const authClient = createClient(
  SUPABASE_URL, SUPABASE_ANON_KEY || SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
)
// supabase: SERVICE KEY for all DB queries — server-side only, bypasses RLS
const supabase = createClient(
  SUPABASE_URL, SUPABASE_SERVICE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
)

// ─── BLOCK SOURCE FILE EXPOSURE ────────────────────────────────────────────────
// Prevents serving server.js, package.json, .env, etc.
const BLOCKED_EXTENSIONS = ['.js', '.ts', '.json', '.env', '.md', '.lock', '.sh', '.sql', '.yaml', '.yml']
const ALLOWED_STATIC = ['/index.html', '/favicon.ico', '/robots.txt']
app.use((req, res, next) => {
  const p = req.path.toLowerCase()
  // Always allow HTML and the root
  if (p === '/' || ALLOWED_STATIC.includes(p)) return next()
  // Always allow /api/ routes
  if (p.startsWith('/api/')) return next()
  // Block any source file types
  if (BLOCKED_EXTENSIONS.some(ext => p.endsWith(ext))) {
    return res.status(404).send('Not found')
  }
  next()
})

// ─── STATIC — serve /public dir and root for index.html ──────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  index: false,
  dotfiles: 'deny'
}))
// Also serve root-level index.html if it exists there
app.use(express.static(path.join(__dirname), {
  index: false,
  dotfiles: 'deny'
}))

// ─── AUTH MIDDLEWARE ────────────────────────────────────────────────────────────
async function auth(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' })
  }
  const token = authHeader.replace('Bearer ', '').trim()
  if (!token || token.length < 10) {
    return res.status(401).json({ error: 'Invalid token format' })
  }
  try {
    // Use authClient (anon key) to validate user tokens — service key getUser behaves differently
    const { data: { user }, error } = await authClient.auth.getUser(token)
    if (error || !user) return res.status(401).json({ error: 'Session expired. Please sign in again.' })
    const { data: profile, error: profileErr } = await supabase
      .from('user_profiles')
      .select('*')
      .eq('id', user.id)
      .single()
    if (profileErr || !profile) return res.status(401).json({ error: 'User profile not found. Contact administrator.' })
    if (profile.is_active === false) {
      return res.status(403).json({ error: 'Your account has been disabled. Contact your administrator.' })
    }
    req.user = profile
    next()
  } catch (err) {
    return res.status(500).json({ error: 'Authentication service error' })
  }
}

const requireAdmin = (req, res, next) =>
  ['super_admin', 'admin'].includes(req.user?.role)
    ? next()
    : res.status(403).json({ error: 'Admin access required' })

const requireSuper = (req, res, next) =>
  req.user?.role === 'super_admin'
    ? next()
    : res.status(403).json({ error: 'Super admin access required' })

// ─── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/login', rateLimitLogin, async (req, res) => {
  // Always return JSON — never crash silently
  try {
    const { email, password } = req.body || {}
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' })
    }
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid input format' })
    }
    const cleanEmail = email.trim().toLowerCase()

    // Use authClient (anon key) for signInWithPassword — correct Supabase pattern
    const { data, error } = await authClient.auth.signInWithPassword({
      email: cleanEmail, password
    })

    if (error || !data?.session) {
      console.log('Login failed for:', cleanEmail, error?.message)
      return res.status(401).json({ error: 'Invalid email or password' })
    }

    // Fetch user profile from DB using service key
    const { data: profile, error: profileErr } = await supabase
      .from('user_profiles').select('*').eq('id', data.user.id).single()

    if (profileErr || !profile) {
      console.error('Profile fetch failed:', profileErr?.message)
      return res.status(401).json({ error: 'User profile not found. Contact administrator.' })
    }

    if (profile.is_active === false) {
      return res.status(403).json({ error: 'Account disabled. Contact your administrator.' })
    }

    // Update last login timestamp
    await supabase.from('user_profiles')
      .update({ last_login_at: new Date().toISOString() })
      .eq('id', data.user.id).catch(() => {})

    // Log activity
    await supabase.from('activity_log').insert({
      user_id: data.user.id, action: 'USER_LOGIN',
      details: `Login from ${req.headers['x-forwarded-for']?.split(',')[0] || 'unknown'}`
    }).catch(() => {})

    return res.json({ token: data.session.access_token, user: profile })
  } catch (err) {
    console.error('Login route error:', err)
    return res.status(500).json({ error: 'Login service error. Please try again.' })
  }
})

app.post('/api/logout', auth, async (req, res) => {
  await authClient.auth.signOut().catch(() => {})
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'USER_LOGOUT', details: 'User signed out'
  }).catch(() => {})
  res.json({ success: true })
})

// ─── CHANGE OWN PASSWORD ───────────────────────────────────────────────────────
app.post('/api/change-password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body
    if (!new_password || new_password.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' })
    }
    // Re-authenticate with current password to verify identity
    const { error: authErr } = await authClient.auth.signInWithPassword({
      email: req.user.email, password: current_password
    })
    if (authErr) {
      return res.status(401).json({ error: 'Current password is incorrect' })
    }
    // Update password using admin (service) client
    const { error } = await supabase.auth.admin.updateUserById(req.user.id, {
      password: new_password
    })
    if (error) return res.status(400).json({ error: error.message })
    await supabase.from('activity_log').insert({
      user_id: req.user.id, action: 'CHANGE_PASSWORD', details: 'User changed their own password'
    }).catch(() => {})
    res.json({ success: true, message: 'Password changed successfully' })
  } catch (err) {
    console.error('Change password error:', err)
    res.status(500).json({ error: 'Password change failed. Please try again.' })
  }
})

// ─── ADMIN RESET USER PASSWORD ─────────────────────────────────────────────────
app.post('/api/users/:id/reset-password', auth, requireAdmin, async (req, res) => {
  try {
    const { new_password } = req.body
    if (!new_password || new_password.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' })
    }
    const { data: target } = await supabase.from('user_profiles')
      .select('email,full_name').eq('id', req.params.id).single()
    if (!target) return res.status(404).json({ error: 'User not found' })

    const { error } = await supabase.auth.admin.updateUserById(req.params.id, {
      password: new_password
    })
    if (error) return res.status(400).json({ error: error.message })

    await supabase.from('activity_log').insert({
      user_id: req.user.id, action: 'RESET_PASSWORD',
      record_type: 'user_profiles', record_id: req.params.id,
      details: `Admin reset password for: ${target.email}`
    }).catch(() => {})
    res.json({ success: true, message: `Password reset for ${target.email}` })
  } catch (err) {
    console.error('Reset password error:', err)
    res.status(500).json({ error: 'Password reset failed. Please try again.' })
  }
})

app.get('/api/me', auth, (req, res) => res.json(req.user))
app.get('/api/health', (req, res) => res.json({ status: 'ok', ts: new Date().toISOString() }))

// ─── WIBs ──────────────────────────────────────────────────────────────────────
app.get('/api/wibs', auth, async (req, res) => {
  const { state, status, search, limit = 200, offset = 0 } = req.query
  let q = supabase.from('wib_records')
    .select('*, owner:user_profiles!owner_id(full_name,email)', { count: 'exact' })
  if (state) q = q.eq('state', state)
  if (status) q = q.eq('status', status)
  if (search) q = q.ilike('wib_name', `%${search}%`)
  q = q.order('call_priority_score', { ascending: false })
    .range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.get('/api/wibs/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('wib_records')
    .select('*, owner:user_profiles!owner_id(full_name,email)')
    .eq('id', req.params.id).single()
  if (error) return res.status(404).json({ error: 'Not found' })
  res.json(data)
})

app.post('/api/wibs', auth, async (req, res) => {
  const allowed = ['wib_name','short_name','state','status','wib_phone','wib_email','website',
    'max_award_per_ein','match_requirement_pct','wib_type','source_url','google_drive_folder_url',
    'next_steps','blockers','notes','iwt_program_active','independent_creation_logged','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.wib_name?.trim()) return res.status(400).json({ error: 'WIB name required' })
  if (!body.source_url?.trim()) return res.status(400).json({ error: 'Source URL required (public government page)' })
  const { data, error } = await supabase.from('wib_records')
    .insert({ ...body, owner_id: req.user.id })
    .select('*, owner:user_profiles!owner_id(full_name,email)').single()
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'CREATE_WIB', record_type: 'wib_records',
    record_id: data.id, details: `Created WIB: ${data.wib_name}`
  }).catch(() => {})
  res.json(data)
})

app.put('/api/wibs/:id', auth, async (req, res) => {
  const allowed = ['wib_name','short_name','state','status','wib_phone','wib_email','website',
    'max_award_per_ein','match_requirement_pct','wib_type','source_url','google_drive_folder_url',
    'next_steps','blockers','notes','iwt_program_active','independent_creation_logged','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('wib_records')
    .update(body).eq('id', req.params.id)
    .select('*, owner:user_profiles!owner_id(full_name,email)').single()
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'UPDATE_WIB', record_type: 'wib_records',
    record_id: req.params.id, details: `Updated WIB: ${data.wib_name}`
  }).catch(() => {})
  res.json(data)
})

app.delete('/api/wibs/:id', auth, requireAdmin, async (req, res) => {
  const { data: wib } = await supabase.from('wib_records').select('wib_name').eq('id', req.params.id).single()
  const { error } = await supabase.from('wib_records').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'DELETE_WIB', details: `Deleted WIB: ${wib?.wib_name}`
  }).catch(() => {})
  res.json({ success: true })
})

// ─── COMPANIES ─────────────────────────────────────────────────────────────────
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
  const allowed = ['company_name','company_type','status','fein','domain','employee_count_total',
    'avg_hourly_wage','primary_contact_name','primary_contact_email','primary_contact_phone',
    'training_needs','notes','rating']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.company_name?.trim()) return res.status(400).json({ error: 'Company name required' })
  const { data, error } = await supabase.from('companies').insert(body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'CREATE_COMPANY', record_type: 'companies',
    record_id: data.id, details: `Created company: ${data.company_name}`
  }).catch(() => {})
  res.json(data)
})

app.put('/api/companies/:id', auth, async (req, res) => {
  const allowed = ['company_name','company_type','status','fein','domain','employee_count_total',
    'avg_hourly_wage','primary_contact_name','primary_contact_email','primary_contact_phone',
    'training_needs','notes','rating']
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

// ─── LOCATIONS ─────────────────────────────────────────────────────────────────
app.get('/api/locations', auth, async (req, res) => {
  const { state, status, wib_id, search, limit = 200, offset = 0 } = req.query
  let q = supabase.from('locations')
    .select('*, parent_company:companies(company_name), wib:wib_records(wib_name,state)', { count: 'exact' })
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
  const allowed = ['location_name','state','county','city','status','employee_count',
    'company_id','wib_id','notes','address']
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

// ─── FUNDING OPPORTUNITIES ─────────────────────────────────────────────────────
app.get('/api/funding', auth, async (req, res) => {
  const { status, wib_id, search, limit = 200, offset = 0 } = req.query
  let q = supabase.from('funding_opportunities')
    .select('*, wib:wib_records(id,wib_name,state)', { count: 'exact' })
  if (status) q = q.eq('status', status)
  if (wib_id) q = q.eq('wib_id', wib_id)
  if (search) q = q.ilike('opportunity_name', `%${search}%`)
  q = q.order('created_at', { ascending: false }).range(+offset, +offset + Math.min(+limit, 500) - 1)
  const { data, error, count } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/funding', auth, async (req, res) => {
  const allowed = ['opportunity_name','wib_id','status','program_type','max_award_per_ein',
    'application_deadline','application_link','source_url','notes',
    'independent_creation_logged','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.opportunity_name?.trim()) return res.status(400).json({ error: 'Opportunity name required' })
  if (!body.source_url?.trim()) return res.status(400).json({ error: 'Source URL required' })
  const { data, error } = await supabase.from('funding_opportunities').insert(body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'CREATE_FUNDING', record_type: 'funding_opportunities',
    record_id: data.id, details: `Created funding opportunity: ${data.opportunity_name}`
  }).catch(() => {})
  res.json(data)
})

app.put('/api/funding/:id', auth, async (req, res) => {
  const allowed = ['opportunity_name','status','program_type','max_award_per_ein',
    'application_deadline','application_link','source_url','notes','last_verified_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('funding_opportunities')
    .update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/funding/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('funding_opportunities').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── APPLICATIONS ──────────────────────────────────────────────────────────────
app.get('/api/applications', auth, async (req, res) => {
  const { status, limit = 200, offset = 0 } = req.query
  let q = supabase.from('applications').select(`
    *, company:companies(id,company_name), wib:wib_records(id,wib_name,state),
    funding_opportunity:funding_opportunities(id,opportunity_name),
    revenue:revenue_records(fee_model,calculated_success_fee,invoice_status)
  `, { count: 'exact' })
  if (status) q = q.eq('status', status)
  q = q.order('created_at', { ascending: false }).range(+offset, +offset + Math.min(+limit, 200) - 1)
  const { data, error, count } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/applications', auth, async (req, res) => {
  const allowed = ['company_id','wib_id','funding_opportunity_id','status',
    'award_amount_requested','submission_date','notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  if (!body.company_id) return res.status(400).json({ error: 'Company required' })
  if (!body.wib_id) return res.status(400).json({ error: 'WIB required' })
  const { data, error } = await supabase.from('applications')
    .insert({ ...body, owner_id: req.user.id }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'CREATE_APPLICATION', record_type: 'applications',
    record_id: data.id, details: `Created application: ${data.application_number}`
  }).catch(() => {})
  res.json(data)
})

app.put('/api/applications/:id', auth, async (req, res) => {
  const allowed = ['status','award_amount_requested','award_amount_approved',
    'submission_date','decision_date','notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('applications')
    .update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'UPDATE_APPLICATION', record_type: 'applications',
    record_id: req.params.id, details: `Updated application: ${body.status || 'fields updated'}`
  }).catch(() => {})
  res.json(data)
})

app.delete('/api/applications/:id', auth, requireAdmin, async (req, res) => {
  const { error } = await supabase.from('applications').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── COMPLIANCE ────────────────────────────────────────────────────────────────
app.get('/api/compliance', auth, async (req, res) => {
  const { data, error } = await supabase.from('v_compliance_alerts')
    .select('*').order('days_until_final_due')
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.put('/api/compliance/:id', auth, async (req, res) => {
  const allowed = ['final_report_submitted','final_report_submitted_date',
    'attendance_sheets_collected','compliance_notes']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('compliance_records')
    .update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── REVENUE ───────────────────────────────────────────────────────────────────
app.get('/api/revenue/dashboard', auth, async (req, res) => {
  const { data, error } = await supabase.from('v_revenue_dashboard').select('*').single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data || {})
})

app.get('/api/revenue', auth, async (req, res) => {
  const { data, error } = await supabase.from('revenue_records')
    .select('*, company:companies(company_name), wib:wib_records(wib_name)')
    .order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.put('/api/revenue/:id', auth, async (req, res) => {
  const allowed = ['invoice_status','payment_received_date','invoice_sent_date']
  const body = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)))
  const { data, error } = await supabase.from('revenue_records')
    .update(body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'UPDATE_REVENUE', record_type: 'revenue_records',
    record_id: req.params.id, details: `Invoice status: ${body.invoice_status || 'updated'}`
  }).catch(() => {})
  res.json(data)
})

// ─── NOTES ─────────────────────────────────────────────────────────────────────
app.get('/api/notes', auth, async (req, res) => {
  const { record_type, record_id, limit = 50 } = req.query
  let q = supabase.from('activity_log')
    .select('*, user:user_profiles!user_id(full_name,email)')
    .eq('action', 'NOTE')
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

// ─── TASKS ─────────────────────────────────────────────────────────────────────
app.get('/api/tasks', auth, async (req, res) => {
  const { record_id, limit = 100 } = req.query
  let q = supabase.from('activity_log')
    .select('*, user:user_profiles!user_id(full_name)')
    .eq('action', 'TASK')
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
    metadata: { due_date, priority, notes, done: false, assigned_to,
      created_by: req.user.full_name || req.user.email }
  }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.put('/api/tasks/:id', auth, async (req, res) => {
  const { data: existing } = await supabase.from('activity_log')
    .select('metadata').eq('id', req.params.id).single()
  const { data, error } = await supabase.from('activity_log')
    .update({ metadata: { ...(existing?.metadata || {}), ...req.body } })
    .eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── ACTIVITY LOG ──────────────────────────────────────────────────────────────
app.get('/api/activity', auth, async (req, res) => {
  const { record_type, record_id, limit = 100 } = req.query
  let q = supabase.from('activity_log')
    .select('*, user:user_profiles!user_id(full_name,email)')
    .neq('action', 'NOTE').neq('action', 'TASK')
  if (record_type) q = q.eq('record_type', record_type)
  if (record_id) q = q.eq('record_id', record_id)
  q = q.order('created_at', { ascending: false }).limit(Math.min(+limit, 200))
  const { data, error } = await q
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.get('/api/audit', auth, requireAdmin, async (req, res) => {
  const { limit = 100, offset = 0 } = req.query
  const { data, error, count } = await supabase.from('activity_log')
    .select('*, user:user_profiles!user_id(full_name,email)', { count: 'exact' })
    .order('created_at', { ascending: false })
    .range(+offset, +offset + Math.min(+limit, 200) - 1)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

// ─── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/users', auth, requireAdmin, async (req, res) => {
  const { data, error } = await supabase.from('user_profiles')
    .select('id,email,full_name,role,title,phone,is_active,created_at,last_login_at')
    .order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.post('/api/users', auth, requireAdmin, async (req, res) => {
  const { email, password, full_name, role = 'team_member', title, phone } = req.body
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' })
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' })
  const validRoles = ['super_admin','admin','team_member','external_partner']
  if (!validRoles.includes(role)) return res.status(400).json({ error: 'Invalid role' })
  // Only super_admin can create super_admin or admin
  if (['super_admin','admin'].includes(role) && req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Only Super Admin can create Admin or Super Admin accounts' })
  }
  const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY)
  const { data, error } = await admin.auth.admin.createUser({
    email: email.trim().toLowerCase(), password,
    email_confirm: true,
    user_metadata: { full_name }
  })
  if (error) return res.status(400).json({ error: error.message })
  await admin.from('user_profiles').update({
    full_name: full_name || null, role, title: title || null,
    phone: phone || null, is_active: true
  }).eq('id', data.user.id)
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'CREATE_USER', record_type: 'user_profiles',
    record_id: data.user.id, details: `Created user: ${email} (${role})`
  }).catch(() => {})
  const { data: profile } = await admin.from('user_profiles').select('*').eq('id', data.user.id).single()
  res.json({ user: profile })
})

app.put('/api/users/:id', auth, requireAdmin, async (req, res) => {
  const { full_name, role, title, phone, is_active } = req.body
  // Cannot modify own account via this endpoint
  if (req.params.id === req.user.id && (is_active === false || (role && role !== req.user.role))) {
    return res.status(400).json({ error: 'Use profile settings to modify your own account' })
  }
  // Guard last super_admin
  if (is_active === false || (role && role !== 'super_admin')) {
    const { data: target } = await supabase.from('user_profiles').select('role').eq('id', req.params.id).single()
    if (target?.role === 'super_admin') {
      const { count } = await supabase.from('user_profiles')
        .select('*', { count: 'exact', head: true })
        .eq('role', 'super_admin').eq('is_active', true)
      if ((count || 0) <= 1) {
        return res.status(400).json({ error: 'Cannot disable or demote the only active Super Admin' })
      }
    }
  }
  const update = {}
  if (full_name !== undefined) update.full_name = full_name
  if (role !== undefined) update.role = role
  if (title !== undefined) update.title = title
  if (phone !== undefined) update.phone = phone
  if (is_active !== undefined) update.is_active = is_active
  const { data, error } = await supabase.from('user_profiles')
    .update(update).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'UPDATE_USER', record_type: 'user_profiles',
    record_id: req.params.id,
    details: `Updated user: ${data.email}${is_active === false ? ' — ACCOUNT DISABLED' : ''}`
  }).catch(() => {})
  res.json(data)
})

app.delete('/api/users/:id', auth, requireSuper, async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' })
  }
  const { data: target } = await supabase.from('user_profiles')
    .select('email,role').eq('id', req.params.id).single()
  if (!target) return res.status(404).json({ error: 'User not found' })
  if (target.role === 'super_admin') {
    const { count } = await supabase.from('user_profiles')
      .select('*', { count: 'exact', head: true }).eq('role', 'super_admin')
    if ((count || 0) <= 1) {
      return res.status(400).json({ error: 'Cannot delete the only Super Admin' })
    }
  }
  const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY)
  const { error } = await admin.auth.admin.deleteUser(req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  await supabase.from('activity_log').insert({
    user_id: req.user.id, action: 'DELETE_USER',
    details: `PERMANENTLY DELETED USER: ${target.email}`
  }).catch(() => {})
  res.json({ success: true })
})

// ─── CSV/EXCEL EXPORT (real data) ─────────────────────────────────────────────
const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`

app.get('/api/export/:type', auth, async (req, res) => {
  const { type } = req.params
  let rows = [], headers = []
  const filename = `valor-${type}-${new Date().toISOString().split('T')[0]}.csv`
  try {
    if (type === 'wibs') {
      const { data } = await supabase.from('wib_records')
        .select('wib_name,short_name,state,status,wib_phone,wib_email,website,max_award_per_ein,match_requirement_pct,iwt_program_active,source_url,call_priority_score,last_verified_date,next_steps,blockers')
        .order('call_priority_score', { ascending: false })
      headers = ['WIB Name','Short Name','State','Status','Phone','Email','Website',
        'Max Award/EIN','Match %','IWT Active','Source URL','Priority Score','Last Verified','Next Steps','Blockers']
      rows = (data || []).map(r => [
        r.wib_name, r.short_name || '', r.state, r.status,
        r.wib_phone || '', r.wib_email || '', r.website || '',
        r.max_award_per_ein || '', r.match_requirement_pct || '',
        r.iwt_program_active ? 'Yes' : 'No', r.source_url || '',
        r.call_priority_score || 0, r.last_verified_date || '',
        r.next_steps || '', r.blockers || ''
      ])
    } else if (type === 'companies') {
      const { data } = await supabase.from('companies')
        .select('company_name,company_type,status,fein,domain,employee_count_total,avg_hourly_wage,primary_contact_name,primary_contact_email,primary_contact_phone,created_at')
        .order('company_name')
      headers = ['Company Name','Type','Status','FEIN','Domain','Employees','Avg Wage',
        'Contact Name','Contact Email','Contact Phone','Created']
      rows = (data || []).map(r => [
        r.company_name, r.company_type || '', r.status, r.fein || '', r.domain || '',
        r.employee_count_total || '', r.avg_hourly_wage || '',
        r.primary_contact_name || '', r.primary_contact_email || '', r.primary_contact_phone || '',
        r.created_at?.split('T')[0] || ''
      ])
    } else if (type === 'applications') {
      const { data } = await supabase.from('applications')
        .select('application_number,status,award_amount_requested,award_amount_approved,submission_date,decision_date,created_at')
        .order('created_at', { ascending: false })
      headers = ['App Number','Status','Requested ($)','Approved ($)','Submitted','Decision Date','Created']
      rows = (data || []).map(r => [
        r.application_number, r.status, r.award_amount_requested || '',
        r.award_amount_approved || '', r.submission_date || '',
        r.decision_date || '', r.created_at?.split('T')[0] || ''
      ])
    } else if (type === 'funding') {
      const { data } = await supabase.from('funding_opportunities')
        .select('opportunity_name,status,program_type,max_award_per_ein,application_deadline,source_url,created_at')
        .order('created_at', { ascending: false })
      headers = ['Opportunity Name','Status','Program','Max Award/EIN','Deadline','Source URL','Created']
      rows = (data || []).map(r => [
        r.opportunity_name, r.status, r.program_type || '',
        r.max_award_per_ein || '', r.application_deadline || '',
        r.source_url || '', r.created_at?.split('T')[0] || ''
      ])
    } else if (type === 'revenue') {
      const { data } = await supabase.from('revenue_records')
        .select('fee_model,grant_award_amount,calculated_success_fee,invoice_status,payment_received_date,created_at')
        .order('created_at', { ascending: false })
      headers = ['Fee Model','Grant Award','Valor Fee','Invoice Status','Payment Date','Created']
      rows = (data || []).map(r => [
        r.fee_model || '', r.grant_award_amount || '',
        r.calculated_success_fee || '', r.invoice_status || '',
        r.payment_received_date || '', r.created_at?.split('T')[0] || ''
      ])
    } else if (type === 'users') {
      if (!['super_admin', 'admin'].includes(req.user.role)) {
        return res.status(403).json({ error: 'Admin access required to export users' })
      }
      const { data } = await supabase.from('user_profiles')
        .select('full_name,email,role,title,is_active,created_at')
      headers = ['Full Name','Email','Role','Title','Active','Created']
      rows = (data || []).map(r => [
        r.full_name || '', r.email, r.role, r.title || '',
        r.is_active ? 'Yes' : 'No', r.created_at?.split('T')[0] || ''
      ])
    } else if (type === 'locations') {
      const { data } = await supabase.from('locations')
        .select('location_name,state,county,city,status,employee_count,created_at')
        .order('location_name')
      headers = ['Location Name','State','County','City','Status','Employees','Created']
      rows = (data || []).map(r => [
        r.location_name, r.state || '', r.county || '', r.city || '',
        r.status || '', r.employee_count || '', r.created_at?.split('T')[0] || ''
      ])
    } else if (type === 'audit') {
      if (!['super_admin','admin'].includes(req.user.role)) {
        return res.status(403).json({ error: 'Admin access required' })
      }
      const { data } = await supabase.from('activity_log')
        .select('action,details,record_type,created_at,user:user_profiles!user_id(email)')
        .order('created_at', { ascending: false }).limit(1000)
      headers = ['Action','User','Details','Record Type','Timestamp']
      rows = (data || []).map(r => [
        r.action, r.user?.email || '', r.details || '',
        r.record_type || '', r.created_at || ''
      ])
    } else {
      return res.status(400).json({ error: 'Unknown export type' })
    }
    await supabase.from('activity_log').insert({
      user_id: req.user.id, action: 'EXPORT',
      details: `Exported ${type} — ${rows.length} records`
    }).catch(() => {})
    const csv = [
      headers.map(esc).join(','),
      ...rows.map(r => r.map(esc).join(','))
    ].join('\n')
    res.setHeader('Content-Type', 'text/csv; charset=utf-8')
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)
    res.send(csv)
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

// CSV Import template download
app.get('/api/template/:type', auth, (req, res) => {
  const templates = {
    wibs: 'WIB Name,Short Name,State,Status,Phone,Email,Website,Max Award,Match %,IWT Active,Source URL',
    companies: 'Company Name,Type,Status,FEIN,Domain,Employee Count,Avg Wage,Contact Name,Contact Email,Contact Phone',
    locations: 'Location Name,State,County,City,Status,Employee Count',
    funding: 'Opportunity Name,Status,Program Type,Max Award/EIN,Deadline,Source URL',
  }
  const csv = templates[req.params.type]
  if (!csv) return res.status(400).json({ error: 'Unknown template type' })
  res.setHeader('Content-Type', 'text/csv')
  res.setHeader('Content-Disposition', `attachment; filename="valor-${req.params.type}-template.csv"`)
  res.send(csv)
})

// ─── SERVE FRONTEND ────────────────────────────────────────────────────────────
// Check multiple locations for index.html — handles root or /public/ placement
app.get('*', (req, res) => {
  const candidates = [
    path.join(__dirname, 'public', 'index.html'),
    path.join(__dirname, 'index.html'),
  ]
  for (const htmlPath of candidates) {
    if (fs.existsSync(htmlPath)) {
      res.setHeader('X-Content-Type-Options', 'nosniff')
      console.log('Serving:', htmlPath)
      return res.sendFile(htmlPath)
    }
  }
  res.status(503).send(`
    <html><body style="font-family:sans-serif;padding:40px;text-align:center">
    <h2>🛡️ Valor CRM</h2>
    <p>Platform loading. Please try again in 60 seconds.</p>
    <p style="color:#999;font-size:12px">If this persists, check deployment logs on Render.</p>
    </body></html>
  `)
})

// ─── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`✅ Valor CRM — Production — Port ${PORT}`)
  console.log(`   Security headers: enabled`)
  console.log(`   Rate limiting: enabled (8 attempts / 15 min)`)
  console.log(`   Source file blocking: enabled`)
  console.log(`   Static files: /public only`)
})
