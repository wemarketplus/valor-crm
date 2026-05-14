const express = require('express')
const { createClient } = require('@supabase/supabase-js')
const path = require('path')
const app = express()

app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
)

// ─── AUTH ───────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body
  const { data, error } = await supabase.auth.signInWithPassword({ email, password })
  if (error) return res.status(401).json({ error: error.message })
  res.json({ token: data.session.access_token, user: data.user })
})

// ─── MIDDLEWARE ─────────────────────────────────────────
async function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) return res.status(401).json({ error: 'No token' })
  const { data: { user }, error } = await supabase.auth.getUser(token)
  if (error || !user) return res.status(401).json({ error: 'Invalid token' })
  const { data: profile } = await supabase.from('user_profiles').select('*').eq('id', user.id).single()
  req.user = profile
  req.userClient = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${token}` } }
  })
  next()
}

// ─── WIB RECORDS ────────────────────────────────────────
app.get('/api/wibs', auth, async (req, res) => {
  const { state, status, search, limit = 100, offset = 0 } = req.query
  let query = supabase.from('wib_records').select('*', { count: 'exact' })
  if (state) query = query.eq('state', state)
  if (status) query = query.eq('status', status)
  if (search) query = query.ilike('wib_name', `%${search}%`)
  query = query.order('call_priority_score', { ascending: false }).range(Number(offset), Number(offset) + Number(limit) - 1)
  const { data, error, count } = await query
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/wibs', auth, async (req, res) => {
  const { data, error } = await supabase.from('wib_records').insert(req.body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.put('/api/wibs/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('wib_records').update(req.body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/wibs/:id', auth, async (req, res) => {
  if (!['super_admin','admin'].includes(req.user?.role)) return res.status(403).json({ error: 'Forbidden' })
  const { error } = await supabase.from('wib_records').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── COMPANIES ──────────────────────────────────────────
app.get('/api/companies', auth, async (req, res) => {
  const { search, status, limit = 100, offset = 0 } = req.query
  let query = supabase.from('companies').select('*', { count: 'exact' })
  if (status) query = query.eq('status', status)
  if (search) query = query.ilike('company_name', `%${search}%`)
  query = query.order('created_at', { ascending: false }).range(Number(offset), Number(offset) + Number(limit) - 1)
  const { data, error, count } = await query
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/companies', auth, async (req, res) => {
  const { data, error } = await supabase.from('companies').insert(req.body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.put('/api/companies/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('companies').update(req.body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── LOCATIONS ──────────────────────────────────────────
app.get('/api/locations', auth, async (req, res) => {
  const { state, status, search, wib_id, limit = 100, offset = 0 } = req.query
  let query = supabase.from('locations').select('*, parent_company:companies(company_name), wib:wib_records(wib_name,state)', { count: 'exact' })
  if (state) query = query.eq('state', state)
  if (status) query = query.eq('status', status)
  if (wib_id) query = query.eq('wib_id', wib_id)
  if (search) query = query.ilike('location_name', `%${search}%`)
  query = query.order('location_name').range(Number(offset), Number(offset) + Number(limit) - 1)
  const { data, error, count } = await query
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/locations', auth, async (req, res) => {
  const { data, error } = await supabase.from('locations').insert(req.body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.put('/api/locations/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('locations').update(req.body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── FUNDING OPPORTUNITIES ──────────────────────────────
app.get('/api/funding', auth, async (req, res) => {
  const { status, search, limit = 100, offset = 0 } = req.query
  let query = supabase.from('funding_opportunities').select('*, wib:wib_records(wib_name,state)', { count: 'exact' })
  if (status) query = query.eq('status', status)
  if (search) query = query.ilike('opportunity_name', `%${search}%`)
  query = query.order('created_at', { ascending: false }).range(Number(offset), Number(offset) + Number(limit) - 1)
  const { data, error, count } = await query
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/funding', auth, async (req, res) => {
  const { data, error } = await supabase.from('funding_opportunities').insert(req.body).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.put('/api/funding/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('funding_opportunities').update(req.body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/funding/:id', auth, async (req, res) => {
  if (!['super_admin','admin'].includes(req.user?.role)) return res.status(403).json({ error: 'Forbidden' })
  const { error } = await supabase.from('funding_opportunities').delete().eq('id', req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── APPLICATIONS ───────────────────────────────────────
app.get('/api/applications', auth, async (req, res) => {
  const { status, limit = 100, offset = 0 } = req.query
  let query = supabase.from('applications').select(`
    *, company:companies(company_name), wib:wib_records(wib_name,state),
    funding_opportunity:funding_opportunities(opportunity_name),
    revenue:revenue_records(fee_model,calculated_success_fee,invoice_status)
  `, { count: 'exact' })
  if (status) query = query.eq('status', status)
  query = query.order('created_at', { ascending: false }).range(Number(offset), Number(offset) + Number(limit) - 1)
  const { data, error, count } = await query
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data, count })
})

app.post('/api/applications', auth, async (req, res) => {
  const { data, error } = await supabase.from('applications').insert({ ...req.body, owner_id: req.user.id }).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.put('/api/applications/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('applications').update(req.body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── COMPLIANCE ─────────────────────────────────────────
app.get('/api/compliance', auth, async (req, res) => {
  const { data, error } = await supabase.from('v_compliance_alerts').select('*').order('days_until_final_due')
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.put('/api/compliance/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('compliance_records').update(req.body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── REVENUE ────────────────────────────────────────────
app.get('/api/revenue/dashboard', auth, async (req, res) => {
  const { data, error } = await supabase.from('v_revenue_dashboard').select('*').single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.get('/api/revenue', auth, async (req, res) => {
  const { data, error } = await supabase.from('revenue_records').select(`
    *, company:companies(company_name), wib:wib_records(wib_name)
  `).order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.put('/api/revenue/:id', auth, async (req, res) => {
  const { data, error } = await supabase.from('revenue_records').update(req.body).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

// ─── USERS (admin only) ─────────────────────────────────
app.get('/api/users', auth, async (req, res) => {
  if (!['super_admin','admin'].includes(req.user?.role)) return res.status(403).json({ error: 'Forbidden' })
  const { data, error } = await supabase.from('user_profiles').select('*').order('created_at', { ascending: false })
  if (error) return res.status(400).json({ error: error.message })
  res.json({ data })
})

app.post('/api/users', auth, async (req, res) => {
  if (!['super_admin','admin'].includes(req.user?.role)) return res.status(403).json({ error: 'Forbidden' })
  const { email, password, full_name, role, title, phone } = req.body
  const adminSupabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY)
  const { data, error } = await adminSupabase.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { full_name } })
  if (error) return res.status(400).json({ error: error.message })
  await adminSupabase.from('user_profiles').update({ full_name, role, title, phone }).eq('id', data.user.id)
  const { data: profile } = await adminSupabase.from('user_profiles').select('*').eq('id', data.user.id).single()
  res.json({ user: profile })
})

app.put('/api/users/:id', auth, async (req, res) => {
  if (!['super_admin','admin'].includes(req.user?.role)) return res.status(403).json({ error: 'Forbidden' })
  const { full_name, role, title, phone, is_active } = req.body
  const { data, error } = await supabase.from('user_profiles').update({ full_name, role, title, phone, is_active }).eq('id', req.params.id).select().single()
  if (error) return res.status(400).json({ error: error.message })
  res.json(data)
})

app.delete('/api/users/:id', auth, async (req, res) => {
  if (req.user?.role !== 'super_admin') return res.status(403).json({ error: 'Super admin only' })
  const adminSupabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY)
  const { error } = await adminSupabase.auth.admin.deleteUser(req.params.id)
  if (error) return res.status(400).json({ error: error.message })
  res.json({ success: true })
})

// ─── ME ─────────────────────────────────────────────────
app.get('/api/me', auth, async (req, res) => { res.json(req.user) })

// ─── SERVE FRONTEND ─────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

const PORT = process.env.PORT || 3001
app.listen(PORT, () => console.log(`Valor CRM running on port ${PORT}`))
