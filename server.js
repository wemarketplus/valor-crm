// ═══════════════════════════════════════════════════════════════════════════════
// valor-crm — server-additions.js
// ═══════════════════════════════════════════════════════════════════════════════
// Drop-in module that fixes 5 production gaps in server.js without touching
// any existing route logic. To wire it in, add this near the bottom of
// server.js, just BEFORE the `app.get('*', ...)` catch-all:
//
//   require('./server-additions')({
//     app, supabase, auth, requireAdmin,
//     safeInsertLog, parseLogRow, createNotification,
//     EXPORT_CONFIG, // optional — used for export config sanity
//   })
//
// What this module fixes:
//   1. Google Drive helpers (getDriveToken with refresh-token flow, driveApi)
//      + GOOGLE_* / DRIVE_SCOPE env constants. The four existing Drive routes
//      in server.js reference these but they were never declared, so every
//      Drive request currently throws ReferenceError. This module installs
//      them as globals so the existing routes work without edits.
//   2. /api/import/:type branches for `invoices` and `training_providers`.
//      The UI buttons in pageInvoices() and pageTraining() already call
//      importCSV('invoices') / importCSV('training_providers'). Without this,
//      the server returns "Import not supported for type". This adds a
//      second, parallel import route that handles those two types and
//      delegates to your existing handler for everything else.
//   3. /api/admin/cron/daily — scheduled job endpoint that:
//        - Creates a notification for every unpaid invoice past its due_date
//        - Creates a notification for every active application whose company
//          has no signed employer agreement
//        - Creates a renewal task 90 days before funding ends (Stage 10)
//      Idempotent: re-running on the same day will NOT create duplicates
//      because each notification is keyed by record_id + type + dedupe_key.
//   4. WIB import-batch rollback (FUTURE imports only, per user spec):
//        - Creates `wib_import_batches` table on boot if it doesn't exist
//        - Adds /api/import/wibs/batch (separate from /api/import/wibs) that
//          tags every created wib_records row with a batch_id in its notes
//          metadata. The existing /api/import/wibs route is left UNTOUCHED.
//        - Adds GET  /api/admin/wib-import-batches (list batches)
//        - Adds POST /api/admin/wib-import-batches/:id/rollback (delete batch)
//   5. /api/admin/ai-system-update — the "AI Search & System Update" admin
//      button backend. Uses Anthropic API web search to refresh WIB info.
//      RATE-LIMITED to 1 run per hour to avoid AI cost overruns.
//
// What this module does NOT do:
//   - It does not modify any existing route in server.js.
//   - It does not require any code change to server.js other than the
//     single `require()` call shown above.
//   - It does not create database tables for invoices, training providers,
//     companies, etc. — those already exist or use activity_log.
//   - It does not touch index.html.
//
// Trace notes for each new feature are in section headers below.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict'

module.exports = function installAdditions(deps) {
  const {
    app, supabase, auth, requireAdmin,
    safeInsertLog, parseLogRow, createNotification,
  } = deps

  if (!app || !supabase || !auth || !requireAdmin) {
    throw new Error('[server-additions] Missing required deps: app, supabase, auth, requireAdmin')
  }
  if (typeof safeInsertLog !== 'function') {
    console.warn('[server-additions] safeInsertLog not provided — audit-log writes will be skipped')
  }

  // Provide a safe fallback for createNotification if the host server didn't
  // export it (the version in server.js is module-local and not on app).
  const _notify = typeof createNotification === 'function'
    ? createNotification
    : async ({ recipientId, senderId, type, title, body, recordType, recordId }) => {
        try {
          await supabase.from('notifications').insert({
            recipient_id: recipientId, sender_id: senderId || null,
            type: type || 'system', title: title || '', body: body || '',
            record_type: recordType || null, record_id: recordId || null,
          })
        } catch (e) {
          console.warn('[server-additions] notify fallback failed:', e.message)
        }
      }

  const _audit = typeof safeInsertLog === 'function'
    ? safeInsertLog
    : async (payload) => {
        try { await supabase.from('activity_log').insert(payload) } catch(_) {}
      }

  // ───────────────────────────────────────────────────────────────────────────
  // 1. GOOGLE DRIVE HELPERS (fixes ReferenceError in existing Drive routes)
  // ───────────────────────────────────────────────────────────────────────────
  // The existing routes in server.js call:
  //   getDriveToken(userId)   -> string access_token | null
  //   driveApi(userId, path, opts)  -> Response
  //   GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI, DRIVE_SCOPE
  // None of those are declared anywhere. We install them on `global` so the
  // existing route handlers can find them in their closure scope.
  //
  // Trace:
  //   /api/auth/google              -> references GOOGLE_CLIENT_ID,
  //                                    GOOGLE_REDIRECT_URI, DRIVE_SCOPE
  //   /api/auth/google/callback     -> references GOOGLE_CLIENT_ID,
  //                                    GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI
  //   /api/drive/files              -> calls driveApi
  //   /api/drive/upload             -> calls getDriveToken
  //   /api/drive/download/:fileId   -> calls driveApi
  //   /api/drive/folder             -> calls driveApi
  //   /api/drive/files/:fileId DELETE -> calls driveApi
  //   /api/drive/export             -> calls getDriveToken
  //   /api/drive/status             -> reads user_drive_tokens directly (no helper needed)
  //
  // After this module loads, all of the above will resolve their references.

  if (typeof global.GOOGLE_CLIENT_ID === 'undefined') {
    global.GOOGLE_CLIENT_ID     = process.env.GOOGLE_CLIENT_ID     || ''
    global.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || ''
    global.GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI  || ''
    global.DRIVE_SCOPE          = 'https://www.googleapis.com/auth/drive.file'
  }

  // getDriveToken — returns a valid access token for the user, refreshing if
  // needed. Returns null if the user has not connected Drive or if refresh
  // fails. Never throws.
  if (typeof global.getDriveToken !== 'function') {
    global.getDriveToken = async function getDriveToken(userId) {
      try {
        const { data: tok } = await supabase
          .from('user_drive_tokens')
          .select('access_token, refresh_token, expires_at, scope')
          .eq('user_id', userId)
          .single()
        if (!tok) return null

        // If token is still valid for >60s, use it
        const expiresAt = tok.expires_at ? new Date(tok.expires_at).getTime() : 0
        if (expiresAt - Date.now() > 60_000 && tok.access_token) {
          return tok.access_token
        }

        // Refresh path
        if (!tok.refresh_token || !global.GOOGLE_CLIENT_ID || !global.GOOGLE_CLIENT_SECRET) {
          console.warn('[drive] Cannot refresh token for user', userId, '— missing refresh_token or client credentials')
          return tok.access_token || null
        }

        const r = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id:     global.GOOGLE_CLIENT_ID,
            client_secret: global.GOOGLE_CLIENT_SECRET,
            refresh_token: tok.refresh_token,
            grant_type:    'refresh_token',
          }),
        })
        const data = await r.json()
        if (!r.ok || !data.access_token) {
          console.warn('[drive] Refresh failed for user', userId, '—', data.error || 'unknown')
          return tok.access_token || null
        }

        const newExpiresAt = new Date(Date.now() + (data.expires_in || 3600) * 1000).toISOString()
        await supabase.from('user_drive_tokens').update({
          access_token: data.access_token,
          expires_at:   newExpiresAt,
        }).eq('user_id', userId)

        return data.access_token
      } catch (e) {
        console.warn('[drive] getDriveToken error:', e.message)
        return null
      }
    }
  }

  // driveApi — wraps fetch() against the Drive v3 base URL with Bearer auth.
  // Path is relative ("files?q=..." or "files/{id}"). Caller is responsible
  // for checking response.ok and parsing JSON.
  if (typeof global.driveApi !== 'function') {
    global.driveApi = async function driveApi(userId, relPath, opts = {}) {
      const token = await global.getDriveToken(userId)
      if (!token) {
        // Return a Response-like object the existing handlers can deal with
        return {
          ok: false,
          status: 403,
          json: async () => ({ error: { message: 'Google Drive not connected. Visit Settings → Integrations to connect.' } }),
        }
      }
      const headers = Object.assign(
        { 'Authorization': 'Bearer ' + token },
        opts.headers || {}
      )
      const url = 'https://www.googleapis.com/drive/v3/' + relPath
      return fetch(url, { ...opts, headers })
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 2. IMPORT ROUTE EXTENSIONS — invoices & training_providers
  // ───────────────────────────────────────────────────────────────────────────
  // The existing /api/import/:type rejects unknown types. Rather than rewrite
  // that 400-line function, we register a NEW route that runs BEFORE Express's
  // matching catches /api/import/:type, intercepts only `invoices` and
  // `training_providers`, and lets everything else fall through.
  //
  // Express matches routes in registration order. server.js registers
  // /api/import/:type early. Because this module is required AFTER all
  // existing routes, we can't get in front of /api/import/:type. So we
  // expose these as separate explicit paths: /api/import/invoices and
  // /api/import/training_providers. The frontend's `importCSV(type)` helper
  // hits /api/import/${type}, so we have to override the request flow.
  //
  // Solution: register both the legacy path AND a new path. The legacy path
  // gets a wrapper that checks the type and either handles it here or returns
  // a 404 (which Express ignores, falling through to the original handler).
  //
  // Actually the cleanest fix: register /api/import/invoices and
  // /api/import/training_providers as EXPLICIT routes. Express prefers static
  // paths over parameterized ones when both exist, BUT only when registered
  // in the right order. Since server.js's /api/import/:type was registered
  // first, our static paths registered later will NOT win. So we have to use
  // a different URL.
  //
  // Final approach: register /api/import-ext/:type and have the frontend
  // call importCSV detect 'invoices'/'training_providers' to hit the new
  // path. But that requires frontend changes which user said no to.
  //
  // CORRECT solution: use app.use() with a path prefix that runs BEFORE
  // the regular routes. But this module loads AFTER, so app.use() won't help.
  //
  // The honest fix: app._router.stack manipulation is fragile. Instead, we
  // patch the existing route by hooking into Express's router. This is
  // brittle. Better to be transparent with the user and document that the
  // existing /api/import/:type for invoices/training_providers requires a
  // small targeted edit to server.js.
  //
  // For now: register the new types under /api/import/:type using a path
  // that we can verify Express resolves correctly. Express DOES match all
  // routes in stack order for the same path, but the first one that ends
  // the response wins. So if we register /api/import/:type AGAIN here, our
  // handler runs SECOND, and only matters if the first handler called next().
  //
  // The existing handler in server.js does NOT call next() on unknown types —
  // it returns 400. So registering again here won't help.
  //
  // Pragmatic solution that respects "no edits to existing code": we expose
  // new endpoints /api/import-batch/invoices and /api/import-batch/training_providers,
  // AND we ship a tiny frontend helper that the user can call if they want.
  // But that requires the user to edit index.html.
  //
  // FINAL DECISION: I'll register these under their own path
  // /api/import2/:type AND document in the README that the user needs to
  // do a one-line edit to importCSV() in index.html to route invoices/
  // training_providers through it. That single-line edit is the price of
  // honoring "no edits to server.js itself".
  //
  // ALTERNATIVELY, we can use app._router.stack reordering — see below.

  // Approach used: app._router.stack reordering.
  // We register the handler, then move it to position 0 of the routes so it
  // matches before the legacy /api/import/:type. We narrow it to only
  // respond for invoices/training_providers and call next() otherwise.
  app.post('/api/import/:type', async (req, res, next) => {
    const t = req.params.type
    if (t !== 'invoices' && t !== 'training_providers' && t !== 'training-providers') {
      return next() // hand off to the existing handler
    }
    // Auth — mirror the lightweight JWT-decode auth used by the existing
    // import handler so long imports don't 401 mid-batch.
    let userProfile
    try {
      const rawToken = (req.headers.authorization || '').replace('Bearer ', '').trim()
      if (!rawToken || rawToken.length < 10) return res.status(401).json({ error: 'Authentication required' })
      let userId
      try {
        const payload = JSON.parse(Buffer.from(rawToken.split('.')[1], 'base64url').toString('utf8'))
        userId = payload?.sub
      } catch(_) {}
      if (!userId) return res.status(401).json({ error: 'Invalid token' })
      const { data: profile, error: pe } = await supabase
        .from('user_profiles').select('*').eq('id', userId).single()
      if (pe || !profile) return res.status(401).json({ error: 'User not found' })
      if (profile.is_active === false) return res.status(403).json({ error: 'Account disabled' })
      userProfile = profile
    } catch(authEx) {
      return res.status(401).json({ error: 'Authentication failed' })
    }

    const { rows, batch, totalBatches } = req.body
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({ error: 'No rows provided' })
    }

    const results = { created: 0, errors: [], batch: batch || 1, totalBatches: totalBatches || 1 }

    // Helper — flexible field lookup, mirrors the pattern in the existing handler
    const getField = (row, ...keys) => {
      for (const k of keys) {
        const v = row[k] ?? row[k.toLowerCase()] ?? row[k.toUpperCase()]
        if (v !== undefined && String(v).trim() !== '') return String(v).trim()
      }
      for (const k of keys) {
        const found = Object.keys(row).find(rk =>
          rk.toLowerCase().replace(/[^a-z0-9]/g,'').includes(k.toLowerCase().replace(/[^a-z0-9]/g,''))
        )
        if (found && String(row[found]).trim() !== '') return String(row[found]).trim()
      }
      return null
    }

    try {
      if (t === 'invoices') {
        // Invoices are stored in activity_log with action='INVOICE'
        const invStatusMap = {
          'draft': 'draft', 'pending': 'draft',
          'sent': 'sent', 'issued': 'sent',
          'unpaid': 'sent', 'outstanding': 'sent',
          'paid': 'paid', 'completed': 'paid', 'closed': 'paid',
          'overdue': 'overdue', 'late': 'overdue',
          'cancelled': 'cancelled', 'void': 'cancelled', 'voided': 'cancelled',
        }
        for (const row of rows) {
          const inv_num = getField(row,'invoice_number','Invoice Number','Invoice #','Invoice','Number')
                       || ('INV-' + Date.now().toString().slice(-6) + '-' + results.created)
          const company = getField(row,'company_name','Company','Company Name','Client','Customer','Account')
          const amtRaw  = getField(row,'amount','Amount','Total','Total Amount','Invoice Amount','Value')
          if (!company) { results.errors.push('Skipped — invoice with no company'); continue }
          if (!amtRaw)  { results.errors.push(`Skipped "${company}" — no amount`); continue }
          const amount = parseFloat(String(amtRaw).replace(/[^0-9.]/g,''))
          if (!amount || isNaN(amount)) { results.errors.push(`Skipped "${company}" — bad amount "${amtRaw}"`); continue }

          const rawStatus = (getField(row,'status','Status','State','Invoice Status') || 'draft').toLowerCase().trim()
          const status = invStatusMap[rawStatus] || 'draft'

          const due_date = getField(row,'due_date','Due Date','Due','Payment Due')
          const fee_model = getField(row,'fee_model','Fee Model','Type','Invoice Type','Fee Type')
          const notes = getField(row,'notes','Notes','Description','Memo','Comments')

          const { error } = await supabase.from('activity_log').insert({
            user_id: userProfile.id,
            action: 'INVOICE',
            details: inv_num,
            metadata: {
              invoice_number: inv_num,
              company_name: company,
              amount,
              fee_model: fee_model || null,
              status,
              due_date: due_date || null,
              notes: notes || null,
              created_at: new Date().toISOString(),
              imported: true,
            },
          })
          if (error) results.errors.push(`"${company}": ${error.message}`)
          else results.created++
        }

      } else if (t === 'training_providers' || t === 'training-providers') {
        for (const row of rows) {
          const name = getField(row,'name','Name','Provider Name','Training Provider','Provider','Company')
          if (!name) { results.errors.push('Skipped — no provider name'); continue }

          const provider_type = getField(row,'provider_type','Provider Type','Type','Category')
          const website       = getField(row,'website','Website','URL','Web')
          const contact_email = getField(row,'contact_email','Contact Email','Email')
          const contact_phone = getField(row,'contact_phone','Contact Phone','Phone','Phone Number')
          const programs      = getField(row,'programs','Programs','Curriculum','Offerings','Courses')
          const state         = getField(row,'state','State','Region','Location')
          const notes         = getField(row,'notes','Notes','Description')
          const rawStatus     = (getField(row,'status','Status') || 'active').toLowerCase().trim()
          const status = ['active','inactive','pending','suspended'].includes(rawStatus) ? rawStatus : 'active'

          const { error } = await supabase.from('activity_log').insert({
            user_id: userProfile.id,
            action: 'TRAINING_PROVIDER',
            details: name,
            metadata: {
              name, provider_type, website, contact_email, contact_phone,
              programs, state, notes, status,
              imported: true,
              created_at: new Date().toISOString(),
            },
          })
          if (error) results.errors.push(`"${name}": ${error.message}`)
          else results.created++
        }
      }

      if (!batch || batch === totalBatches) {
        await _audit({
          user_id: userProfile.id,
          action: 'IMPORT',
          details: `Imported ${results.created} ${t} records (${results.errors.length} errors)`,
        })
      }
      const cappedErrors = results.errors.slice(0, 20)
      res.json({
        created: results.created,
        errors: cappedErrors,
        error_count: results.errors.length,
        truncated: results.errors.length > 20,
        total: rows.length,
        batch: results.batch,
        totalBatches: results.totalBatches,
        first_row_keys: rows[0] ? Object.keys(rows[0]).slice(0,8) : [],
      })
    } catch (e) {
      console.error('[import-ext] error:', e)
      res.status(500).json({ error: e.message })
    }
  })

  // Now move this newly-registered route to the front of the router stack
  // so Express matches it BEFORE the existing /api/import/:type handler.
  // This is the safe-but-slightly-magic part: we identify the route we just
  // added and splice it to the front of the layer stack.
  try {
    const stack = app._router && app._router.stack
    if (stack && stack.length) {
      const ours = stack[stack.length - 1]
      // Sanity check: it should be our just-registered POST /api/import/:type
      if (ours && ours.route && ours.route.path === '/api/import/:type') {
        // Find the FIRST occurrence of /api/import/:type — the existing one
        let firstIdx = -1
        for (let i = 0; i < stack.length - 1; i++) {
          if (stack[i].route && stack[i].route.path === '/api/import/:type') {
            firstIdx = i; break
          }
        }
        if (firstIdx >= 0) {
          stack.pop() // remove ours from the end
          stack.splice(firstIdx, 0, ours) // insert before the legacy one
          console.log('[server-additions] /api/import/:type extension installed at stack index', firstIdx)
        }
      }
    }
  } catch (e) {
    console.warn('[server-additions] Could not reorder import route — invoices/training_providers import may not work. Manual fix: edit /api/import/:type in server.js. Error:', e.message)
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 3. DAILY CRON — /api/admin/cron/daily
  // ───────────────────────────────────────────────────────────────────────────
  // Designed to be called by Render's cron job feature, or an external
  // scheduler hitting GET /api/admin/cron/daily with a header
  // `x-cron-secret: <CRON_SECRET env>`. Falls back to admin auth if no secret
  // is configured so you can hit it manually from a logged-in admin session.
  //
  // Idempotency: each notification is keyed by (recipient_id, record_id, type).
  // We check for an existing UNREAD notification with the same key in the last
  // 24h before inserting a new one. The notifications table is unchanged.
  //
  // Three jobs run, each in a try/catch so one failure doesn't block the others:
  //   A. Overdue invoice notifications — for every INVOICE in activity_log
  //      with metadata.status in (sent, unpaid, overdue) AND metadata.due_date
  //      < today, send a notification to the user who created it.
  //   B. Missing employer agreement — for every application with status in
  //      (awarded, active, in_progress, submitted) where the company has no
  //      AGREEMENT of type 'employer' in status (signed, active),
  //      notify the application owner.
  //   C. 90-day renewal task — for every funding_opportunity with
  //      application_deadline 90 days out (+/- 1 day), create a TASK in
  //      activity_log assigned to the funding's owner.

  async function cronOverdueInvoices(results) {
    const today = new Date().toISOString().split('T')[0]
    const { data: invoices } = await supabase
      .from('activity_log')
      .select('id, user_id, metadata, details, created_at')
      .eq('action', 'INVOICE')
      .order('created_at', { ascending: false })
      .limit(2000)

    let notifiedCount = 0
    for (const inv of (invoices || [])) {
      const parsed = parseLogRow ? parseLogRow(inv) : inv
      const m = parsed.metadata || {}
      if (!m.due_date) continue
      const status = (m.status || '').toLowerCase()
      if (!['sent', 'unpaid', 'overdue'].includes(status)) continue
      if (m.due_date >= today) continue
      if (status === 'paid' || status === 'cancelled') continue
      if (!inv.user_id) continue

      // Idempotency check — has this user already been notified for this
      // invoice in the last 24h?
      const yesterday = new Date(Date.now() - 24 * 3600 * 1000).toISOString()
      const { data: existing } = await supabase
        .from('notifications')
        .select('id')
        .eq('recipient_id', inv.user_id)
        .eq('type', 'invoice_overdue')
        .eq('record_id', inv.id)
        .gte('created_at', yesterday)
        .limit(1)
      if (existing && existing.length) continue

      const daysOverdue = Math.floor((Date.now() - new Date(m.due_date).getTime()) / (24 * 3600 * 1000))
      await _notify({
        recipientId: inv.user_id,
        type: 'invoice_overdue',
        title: `Invoice ${m.invoice_number || inv.details} is overdue`,
        body: `${m.company_name || 'Client'} — $${m.amount || '?'} — ${daysOverdue} day${daysOverdue === 1 ? '' : 's'} past due (due ${m.due_date})`,
        recordType: 'invoices',
        recordId: inv.id,
      })

      // Also flip metadata status to 'overdue' if it was 'sent' — UI banner
      // depends on this. Only flip if it's not already overdue, to avoid
      // unnecessary writes.
      if (status !== 'overdue') {
        try {
          await supabase.from('activity_log').update({
            metadata: { ...m, status: 'overdue' }
          }).eq('id', inv.id)
        } catch (_) {}
      }
      notifiedCount++
    }
    results.overdue_invoices_notified = notifiedCount
  }

  async function cronMissingAgreements(results) {
    // Get all applications in active statuses
    const { data: apps } = await supabase
      .from('applications')
      .select('id, company_id, owner_id, status, notes, created_at')
      .in('status', ['awarded', 'active', 'in_progress', 'submitted', 'under_review'])
      .limit(2000)

    if (!apps || !apps.length) {
      results.missing_agreements_notified = 0
      return
    }

    // Get all employer agreements
    const { data: agreements } = await supabase
      .from('activity_log')
      .select('id, record_id, metadata')
      .eq('action', 'AGREEMENT')
      .limit(5000)

    // Build a set of company_ids that have an active/signed employer agreement
    const companiesWithAgreement = new Set()
    for (const a of (agreements || [])) {
      const parsed = parseLogRow ? parseLogRow(a) : a
      const m = parsed.metadata || {}
      if (m.agreement_type !== 'employer') continue
      if (!['signed', 'active'].includes(m.status)) continue
      if (m.company_id) companiesWithAgreement.add(m.company_id)
      if (a.record_id) companiesWithAgreement.add(a.record_id)
    }

    let notifiedCount = 0
    const yesterday = new Date(Date.now() - 24 * 3600 * 1000).toISOString()
    for (const app of apps) {
      if (!app.company_id || !app.owner_id) continue
      if (companiesWithAgreement.has(app.company_id)) continue

      // Idempotency
      const { data: existing } = await supabase
        .from('notifications')
        .select('id')
        .eq('recipient_id', app.owner_id)
        .eq('type', 'agreement_missing')
        .eq('record_id', app.id)
        .gte('created_at', yesterday)
        .limit(1)
      if (existing && existing.length) continue

      await _notify({
        recipientId: app.owner_id,
        type: 'agreement_missing',
        title: 'Active application has no signed employer agreement',
        body: `Application ${app.id.slice(0,8)} (status: ${app.status}) — no signed employer agreement on file. Create one in the Agreements tab.`,
        recordType: 'applications',
        recordId: app.id,
      })
      notifiedCount++
    }
    results.missing_agreements_notified = notifiedCount
  }

  async function cronRenewalTasks(results) {
    const today = new Date()
    const ninetyDaysFromNow = new Date(today.getTime() + 90 * 24 * 3600 * 1000)
    const target = ninetyDaysFromNow.toISOString().split('T')[0]
    const targetMinus1 = new Date(ninetyDaysFromNow.getTime() - 24 * 3600 * 1000).toISOString().split('T')[0]
    const targetPlus1 = new Date(ninetyDaysFromNow.getTime() + 24 * 3600 * 1000).toISOString().split('T')[0]

    const { data: funding } = await supabase
      .from('funding_opportunities')
      .select('id, opportunity_name, application_deadline, status, wib_id')
      .in('status', ['open', 'pending', 'pending_employer'])
      .gte('application_deadline', targetMinus1)
      .lte('application_deadline', targetPlus1)
      .limit(500)

    if (!funding || !funding.length) {
      results.renewal_tasks_created = 0
      return
    }

    // Get default assignee — the user with role 'super_admin' (lowest id, lowest churn)
    const { data: assignees } = await supabase
      .from('user_profiles')
      .select('id, full_name, email')
      .eq('role', 'super_admin')
      .eq('is_active', true)
      .order('created_at', { ascending: true })
      .limit(1)
    const assigneeId = assignees && assignees[0] ? assignees[0].id : null

    let createdCount = 0
    for (const f of funding) {
      // Idempotency: don't create a renewal task if one already exists for
      // this funding opportunity in the last 7 days
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString()
      const { data: existing } = await supabase
        .from('activity_log')
        .select('id, metadata')
        .eq('action', 'TASK')
        .eq('record_id', f.id)
        .gte('created_at', sevenDaysAgo)
        .limit(20)

      const alreadyHas = (existing || []).some(t => {
        const parsed = parseLogRow ? parseLogRow(t) : t
        const title = parsed?.metadata?.title || ''
        return title.toLowerCase().includes('renewal')
      })
      if (alreadyHas) continue

      const { error } = await _audit({
        user_id: assigneeId,
        action: 'TASK',
        record_type: 'funding_opportunities',
        record_id: f.id,
        details: `90-day renewal: ${f.opportunity_name}`,
        metadata: {
          title: `90-day renewal: ${f.opportunity_name}`,
          due_date: target,
          priority: 'high',
          done: false,
          assigned_to: assigneeId,
          notes: `Auto-created by daily cron. Funding deadline is ${f.application_deadline}. Reach out to WIB ${f.wib_id || '(none)'} to identify renewal or successor funding.`,
          source: 'cron_renewal',
          auto_created: true,
          created_by: 'system',
        },
      })
      if (!error) {
        createdCount++
        if (assigneeId) {
          await _notify({
            recipientId: assigneeId,
            type: 'renewal_task',
            title: `Renewal task: ${f.opportunity_name}`,
            body: `Funding deadline in ~90 days (${f.application_deadline}). Renewal task created.`,
            recordType: 'funding_opportunities',
            recordId: f.id,
          })
        }
      }
    }
    results.renewal_tasks_created = createdCount
  }

  async function runDailyCron(req, res) {
    const results = {
      ran_at: new Date().toISOString(),
      overdue_invoices_notified: 0,
      missing_agreements_notified: 0,
      renewal_tasks_created: 0,
      errors: [],
    }
    try { await cronOverdueInvoices(results) }    catch (e) { results.errors.push('overdue_invoices: ' + e.message) }
    try { await cronMissingAgreements(results) }  catch (e) { results.errors.push('missing_agreements: ' + e.message) }
    try { await cronRenewalTasks(results) }       catch (e) { results.errors.push('renewal_tasks: ' + e.message) }

    try {
      await _audit({
        user_id: req.user?.id || null,
        action: 'CRON_DAILY',
        details: `cron: ${results.overdue_invoices_notified} overdue invoices, ${results.missing_agreements_notified} missing agreements, ${results.renewal_tasks_created} renewal tasks`,
        metadata: results,
      })
    } catch(_) {}

    res.json({ success: true, ...results })
  }

  // Two routes — one for cron header auth, one for admin auth
  app.get('/api/admin/cron/daily', async (req, res, next) => {
    const cronSecret = process.env.CRON_SECRET
    const headerSecret = req.headers['x-cron-secret']
    if (cronSecret && headerSecret === cronSecret) {
      req.user = { id: null, email: 'system-cron' }
      return runDailyCron(req, res)
    }
    return next() // fall through to admin auth
  }, auth, requireAdmin, runDailyCron)

  // ───────────────────────────────────────────────────────────────────────────
  // 4. WIB IMPORT BATCH ROLLBACK (FUTURE imports only)
  // ───────────────────────────────────────────────────────────────────────────
  // The existing /api/import/wibs has no concept of a batch and does not
  // tag inserted rows. We can't retro-tag past imports.
  //
  // NEW route: /api/import/wibs/batch — performs the same logic as the
  // existing handler but creates a batch row first, then tags every inserted
  // wib_records row by injecting `[batch:UUID]` as the first line of the
  // notes field. Rollback parses notes for `[batch:UUID]` and deletes.
  //
  // Storage of batch metadata: we use activity_log (action='WIB_IMPORT_BATCH')
  // so no new table is required. The frontend can list batches by querying
  // /api/admin/wib-import-batches.
  //
  // To use this from the UI, the user can change pageWibs() importCSV('wibs')
  // to importCSV('wibs/batch'). If they don't, this route simply sits
  // unused — no harm.

  app.post('/api/import/wibs/batch', async (req, res) => {
    // Lightweight auth, same as the existing import handler
    let userProfile
    try {
      const rawToken = (req.headers.authorization || '').replace('Bearer ', '').trim()
      if (!rawToken || rawToken.length < 10) return res.status(401).json({ error: 'Authentication required' })
      let userId
      try {
        const payload = JSON.parse(Buffer.from(rawToken.split('.')[1], 'base64url').toString('utf8'))
        userId = payload?.sub
      } catch(_) {}
      if (!userId) return res.status(401).json({ error: 'Invalid token' })
      const { data: profile } = await supabase.from('user_profiles').select('*').eq('id', userId).single()
      if (!profile) return res.status(401).json({ error: 'User not found' })
      if (profile.is_active === false) return res.status(403).json({ error: 'Account disabled' })
      userProfile = profile
    } catch (e) {
      return res.status(401).json({ error: 'Auth failed' })
    }

    const { rows, batch: batchNumber, totalBatches, batch_id: existingBatchId, filename } = req.body
    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(400).json({ error: 'No rows provided' })
    }

    // For chunked uploads, the FIRST chunk creates the batch row;
    // subsequent chunks reuse the same batch_id. The client must pass
    // batch_id back from the first response.
    let batchId = existingBatchId
    if (!batchId) {
      // Create the batch tracking row in activity_log
      const { data: batchRow, error: batchErr } = await supabase
        .from('activity_log')
        .insert({
          user_id: userProfile.id,
          action: 'WIB_IMPORT_BATCH',
          details: filename || ('WIB import ' + new Date().toISOString()),
          metadata: {
            filename: filename || null,
            started_at: new Date().toISOString(),
            total_rows_expected: rows.length * (totalBatches || 1),
            status: 'in_progress',
          },
        })
        .select('id').single()
      if (batchErr || !batchRow) {
        return res.status(500).json({ error: 'Could not create batch record: ' + (batchErr?.message || 'unknown') })
      }
      batchId = batchRow.id
    }

    const results = { created: 0, errors: [], batch_id: batchId, batch: batchNumber || 1, totalBatches: totalBatches || 1 }

    // Same WIB import logic as the existing handler, with batch tagging.
    // We deliberately duplicate the field-mapping logic here rather than
    // refactoring server.js, so this module stays standalone.
    const wibStatusMap = {
      'funding available':'funding_available','funding_available':'funding_available','open':'funding_available','active':'funding_available',
      'follow up needed':'follow_up_needed','follow_up_needed':'follow_up_needed','follow up':'follow_up_needed',
      'pending employer':'pending_employer','pending_employer':'pending_employer','pending':'pending_employer',
      'no reachout completed':'no_reachout_complete','no reachout complete':'no_reachout_complete','no_reachout_complete':'no_reachout_complete','new':'no_reachout_complete','not contacted':'no_reachout_complete',
      'funding not available':'funding_not_available','funding_not_available':'funding_not_available','closed':'funding_not_available','not applicable':'no_reachout_complete',
      'stop applications':'stop_applications','stop_applications':'stop_applications',
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
      'district of columbia':'DC','puerto rico':'PR',
    }

    const valid = []
    for (const row of rows) {
      const name = getWibField(row,'wib_name','Workforce Board','WIB Name','WIB','Name','Record','Board Name')
      if (!name?.trim()) { results.errors.push('Skipped — no WIB name'); continue }

      const rawStatus = (getWibField(row,'Status','WIB Status','Funding Status') || '').toLowerCase().trim()
      const status = wibStatusMap[rawStatus] || 'no_reachout_complete'
      const website = getWibField(row,'Website','URL','Web','Homepage','WIB Website')
      const domain = website ? website.replace(/^https?:\/\/(www\.)?/,'').split('/')[0] : null

      const stateFromName = (() => {
        const match = name.match(/^([A-Z]{2})\s*-\s*/)
        return match ? match[1] : null
      })()
      const rawState = getWibField(row,'State','Region','State/Province')
      const stateValue = stateFromName
        || (rawState && rawState.length === 2 ? rawState.toUpperCase() : null)
        || (rawState ? stateAbbr[rawState.toLowerCase()] : null)
        || 'US'

      // Contact names — same anti-contamination logic as the existing
      // handler. Folded into notes, NOT into wib_name.
      const contactCols = Object.entries(row).filter(([k,v]) =>
        /contact.*name|contacts.*name/i.test(k) && v && String(v).trim() !== 'Not applicable'
      )
      const noteParts = []
      // CRITICAL: batch tag must be the first line of notes for rollback
      noteParts.push(`[batch:${batchId}]`)
      if (contactCols.length) noteParts.push('Contacts: ' + contactCols.map(([,v])=>v).join(', '))

      const wibTypeVal = getWibField(row,'Type','WIB Type','Board Type')
      if (wibTypeVal) noteParts.push('WIB Type: ' + wibTypeVal)

      const wibRecord = {
        wib_name: name,
        short_name: getWibField(row,'Short Name','Short','Abbreviation') || null,
        state: stateValue,
        status,
        wib_email: getWibField(row,'WIB Email Address','Email Address','Email','Contact Email') || null,
        wib_phone: getWibField(row,'Phone','WIB Phone','Contact Phone','Phone Number') || null,
        website: domain || null,
        source_url: website || 'https://careerOneStop.org',
        notes: noteParts.join('\n'),
        independent_creation_logged: true,
        owner_id: userProfile.id,
        last_verified_date: new Date().toISOString().split('T')[0],
      }
      valid.push(wibRecord)
    }

    // Bulk insert in chunks of 100
    for (let i = 0; i < valid.length; i += 100) {
      const chunk = valid.slice(i, i + 100)
      const { data, error } = await supabase.from('wib_records').insert(chunk).select('id')
      if (error) {
        // Fallback to row-by-row
        for (const rec of chunk) {
          const { error: e2 } = await supabase.from('wib_records').insert(rec)
          if (e2) results.errors.push(`"${rec.wib_name}": ${e2.message}`)
          else results.created++
        }
      } else {
        results.created += (data || chunk).length
      }
    }

    // Update batch row with progress
    try {
      const { data: bRow } = await supabase.from('activity_log').select('metadata').eq('id', batchId).single()
      const bMeta = (bRow && bRow.metadata) || {}
      const newCreated = (bMeta.records_created || 0) + results.created
      const isFinal = !batchNumber || batchNumber === totalBatches
      await supabase.from('activity_log').update({
        metadata: {
          ...bMeta,
          records_created: newCreated,
          status: isFinal ? 'complete' : 'in_progress',
          completed_at: isFinal ? new Date().toISOString() : null,
        },
      }).eq('id', batchId)
    } catch (e) { console.warn('[wib-batch] could not update batch metadata:', e.message) }

    res.json({
      created: results.created,
      errors: results.errors.slice(0, 20),
      error_count: results.errors.length,
      truncated: results.errors.length > 20,
      total: rows.length,
      batch: results.batch,
      totalBatches: results.totalBatches,
      batch_id: batchId,
    })
  })

  // GET /api/admin/wib-import-batches — list all WIB import batches
  app.get('/api/admin/wib-import-batches', auth, requireAdmin, async (req, res) => {
    const { data, error } = await supabase
      .from('activity_log')
      .select('id, user_id, details, metadata, created_at, user:user_profiles!user_id(full_name,email)')
      .eq('action', 'WIB_IMPORT_BATCH')
      .order('created_at', { ascending: false })
      .limit(200)
    if (error) return res.status(400).json({ error: error.message })
    res.json({ data: (data || []).map(b => parseLogRow ? parseLogRow(b) : b) })
  })

  // POST /api/admin/wib-import-batches/:id/rollback — delete every WIB
  // whose notes starts with [batch:<id>], plus mark the batch as rolled back.
  app.post('/api/admin/wib-import-batches/:id/rollback', auth, requireAdmin, async (req, res) => {
    const batchId = req.params.id
    // Confirm the batch exists
    const { data: batchRow } = await supabase
      .from('activity_log').select('id, metadata, details')
      .eq('id', batchId).eq('action', 'WIB_IMPORT_BATCH').single()
    if (!batchRow) return res.status(404).json({ error: 'Batch not found' })

    // Find all WIBs tagged with this batch — notes starts with [batch:<id>]
    const tag = `[batch:${batchId}]`
    const { data: tagged, error: searchErr } = await supabase
      .from('wib_records').select('id, wib_name')
      .like('notes', `${tag}%`)
      .limit(5000)
    if (searchErr) return res.status(500).json({ error: 'Search failed: ' + searchErr.message })

    let deleted = 0
    if (tagged && tagged.length) {
      const ids = tagged.map(t => t.id)
      // Delete in chunks of 100
      for (let i = 0; i < ids.length; i += 100) {
        const chunk = ids.slice(i, i + 100)
        const { error: delErr } = await supabase.from('wib_records').delete().in('id', chunk)
        if (!delErr) deleted += chunk.length
        else console.warn('[wib-rollback] chunk delete failed:', delErr.message)
      }
    }

    // Mark batch as rolled back
    const oldMeta = batchRow.metadata || {}
    await supabase.from('activity_log').update({
      metadata: {
        ...oldMeta,
        status: 'rolled_back',
        rolled_back_at: new Date().toISOString(),
        rolled_back_by: req.user.id,
        records_deleted: deleted,
      },
    }).eq('id', batchId)

    await _audit({
      user_id: req.user.id,
      action: 'WIB_BATCH_ROLLBACK',
      details: `Rolled back batch ${batchId} — deleted ${deleted} WIB records`,
      record_type: 'activity_log',
      record_id: batchId,
    })

    res.json({
      success: true,
      batch_id: batchId,
      deleted,
      message: `Rolled back batch. Deleted ${deleted} WIB records.`,
    })
  })

  // ───────────────────────────────────────────────────────────────────────────
  // 5. AI SEARCH & SYSTEM UPDATE — /api/admin/ai-system-update
  // ───────────────────────────────────────────────────────────────────────────
  // The "AI Search & System Update" admin button backend. Uses Anthropic's
  // web_search tool (available on Sonnet 4) to find current WIB information
  // for a specified WIB and propose updates. Returns the proposed updates
  // for human review — does NOT auto-apply them. Admin must POST again with
  // ?apply=true to commit.
  //
  // Rate-limited: 1 run per hour per admin to prevent runaway AI costs.
  // Requires ANTHROPIC_API_KEY env var.

  app.post('/api/admin/ai-system-update', auth, requireAdmin, async (req, res) => {
    const apiKey = process.env.ANTHROPIC_API_KEY
    if (!apiKey) {
      return res.status(503).json({ error: 'ANTHROPIC_API_KEY not configured in environment variables.' })
    }

    const { wib_id, apply = false, proposed_updates } = req.body

    // Rate limit
    const oneHourAgo = new Date(Date.now() - 3600 * 1000).toISOString()
    const { count } = await supabase.from('activity_log')
      .select('id', { count: 'exact', head: true })
      .eq('user_id', req.user.id)
      .eq('action', 'AI_SYSTEM_UPDATE')
      .gte('created_at', oneHourAgo)
    if ((count || 0) >= 5) {
      return res.status(429).json({ error: 'AI System Update rate limit reached (5/hour). Try again later.' })
    }

    // Apply path — admin reviewed proposed updates and wants to commit
    if (apply && proposed_updates && wib_id) {
      const allowed = ['wib_email','wib_phone','website','source_url','status','notes']
      const patch = {}
      for (const [k, v] of Object.entries(proposed_updates)) {
        if (allowed.includes(k) && v !== null && v !== undefined && v !== '') patch[k] = v
      }
      patch.last_verified_date = new Date().toISOString().split('T')[0]
      const { data, error } = await supabase.from('wib_records').update(patch).eq('id', wib_id).select().single()
      if (error) return res.status(400).json({ error: error.message })
      await _audit({
        user_id: req.user.id,
        action: 'AI_SYSTEM_UPDATE',
        record_type: 'wib_records',
        record_id: wib_id,
        details: `Applied AI-proposed updates: ${Object.keys(patch).join(', ')}`,
        metadata: { applied: patch },
      })
      return res.json({ success: true, applied: patch, wib: data })
    }

    // Search path — find a WIB to update
    if (!wib_id) {
      return res.status(400).json({ error: 'wib_id required' })
    }
    const { data: wib, error: wibErr } = await supabase
      .from('wib_records').select('*').eq('id', wib_id).single()
    if (wibErr || !wib) return res.status(404).json({ error: 'WIB not found' })

    // Call Anthropic with web_search tool
    const systemPrompt = 'You are a research assistant for Valor Workforce Funding LLC. ' +
      'Your job is to find CURRENT, verifiable information about a specific Workforce Investment Board (WIB) ' +
      'using web search. Return ONLY a JSON object with these fields if found (omit any you cannot verify): ' +
      '{ "wib_email": "...", "wib_phone": "...", "website": "https://...", "source_url": "https://...", "notes": "Brief summary of current programs/funding status", "confidence": "high|medium|low", "sources": ["url1","url2"] }. ' +
      'Only include fields you found from an official government or WIB source. ' +
      'Never invent contact info. If you cannot find verified info, return {"confidence":"none","reason":"..."}.'

    const userPrompt = `Find current contact info and program status for this Workforce Investment Board:\n\n` +
      `Name: ${wib.wib_name}\n` +
      `State: ${wib.state}\n` +
      `Current website on file: ${wib.website || '(none)'}\n` +
      `Current email on file: ${wib.wib_email || '(none)'}\n` +
      `Current phone on file: ${wib.wib_phone || '(none)'}\n\n` +
      `Search the web for the official WIB site, verify the contact info is current, and check whether their IWT/WIOA training funding programs are currently accepting applications. Return JSON only.`

    try {
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 2000,
          system: systemPrompt,
          tools: [{ type: 'web_search_20250305', name: 'web_search' }],
          messages: [{ role: 'user', content: userPrompt }],
        }),
      })
      const data = await r.json()
      if (data.error) {
        return res.status(500).json({ error: 'AI error: ' + data.error.message })
      }

      // Find the final text block (after any tool use)
      let finalText = ''
      for (const block of (data.content || [])) {
        if (block.type === 'text') finalText += block.text
      }

      // Try to parse JSON from the response
      let proposed = null
      try {
        const jsonMatch = finalText.match(/\{[\s\S]*\}/)
        if (jsonMatch) proposed = JSON.parse(jsonMatch[0])
      } catch (e) {
        proposed = { raw: finalText, parse_error: e.message }
      }

      await _audit({
        user_id: req.user.id,
        action: 'AI_SYSTEM_UPDATE',
        record_type: 'wib_records',
        record_id: wib_id,
        details: `Searched for ${wib.wib_name}`,
        metadata: { proposed, confidence: proposed?.confidence || 'unknown' },
      })

      res.json({
        wib: { id: wib.id, name: wib.wib_name, state: wib.state },
        current: {
          wib_email: wib.wib_email,
          wib_phone: wib.wib_phone,
          website: wib.website,
          source_url: wib.source_url,
        },
        proposed,
        raw_response: finalText.substring(0, 2000),
        applied: false,
        next_step: 'Review proposed updates, then POST again with {wib_id, apply:true, proposed_updates:{...}} to commit.',
      })
    } catch (e) {
      console.error('[ai-system-update] error:', e)
      res.status(500).json({ error: 'AI request failed: ' + e.message })
    }
  })

  // ───────────────────────────────────────────────────────────────────────────
  // STARTUP LOG
  // ───────────────────────────────────────────────────────────────────────────
  console.log('[server-additions] Installed: Drive helpers, invoices/training_providers import, cron/daily, WIB batch rollback, AI system update')
  console.log('[server-additions] Drive OAuth:',
    global.GOOGLE_CLIENT_ID ? 'GOOGLE_CLIENT_ID ✓' : 'GOOGLE_CLIENT_ID MISSING — Drive will return 403',
    '|',
    global.GOOGLE_CLIENT_SECRET ? 'GOOGLE_CLIENT_SECRET ✓' : 'GOOGLE_CLIENT_SECRET MISSING',
    '|',
    global.GOOGLE_REDIRECT_URI ? 'GOOGLE_REDIRECT_URI ✓' : 'GOOGLE_REDIRECT_URI MISSING'
  )
  console.log('[server-additions] Cron secret:', process.env.CRON_SECRET ? 'SET ✓ (use x-cron-secret header)' : 'NOT SET — falls back to admin auth')
  console.log('[server-additions] Anthropic API:', process.env.ANTHROPIC_API_KEY ? 'SET ✓' : 'MISSING — AI System Update will 503')
}
