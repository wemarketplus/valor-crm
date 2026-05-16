require('dotenv').config()

const express = require('express')
const cors = require('cors')
const { Pool } = require('pg')

const app = express()

/* ═══════════════════════════════
   MIDDLEWARE
═══════════════════════════════ */

app.use(cors())
app.use(express.json({ limit: '10mb' }))

/* ═══════════════════════════════
   DATABASE POOL (SAFE)
═══════════════════════════════ */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false
})

/* ═══════════════════════════════
   SAFE DB CONNECT (RETRY LOOP)
═══════════════════════════════ */

async function connectDB(retries = 10, delay = 3000) {
  for (let i = 0; i < retries; i++) {
    try {
      await pool.query('SELECT 1')
      console.log('✅ Database connected')
      return true
    } catch (err) {
      console.log(`⏳ DB not ready (attempt ${i + 1})`)
      await new Promise(res => setTimeout(res, delay))
    }
  }

  throw new Error('❌ Database connection failed after retries')
}

/* ═══════════════════════════════
   MIGRATIONS (SAFE + IDENTITY PROOF)
═══════════════════════════════ */

async function runMigrations() {
  console.log('🔄 Running migrations...')

  await pool.query(`
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS territories (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL UNIQUE,
      states TEXT[] DEFAULT '{}',
      description TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      record_type TEXT NOT NULL,
      record_id UUID NOT NULL,
      title TEXT NOT NULL,
      due_date DATE,
      priority TEXT DEFAULT 'medium',
      assignee_id UUID,
      notes TEXT DEFAULT '',
      completed BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID,
      title TEXT NOT NULL,
      message TEXT DEFAULT '',
      type TEXT DEFAULT 'info',
      is_read BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `)

  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      sender_id UUID,
      channel TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `)

  console.log('✅ Migrations complete')
}

/* ═══════════════════════════════
   API ROUTES
═══════════════════════════════ */

/* HEALTH CHECK (Render uses this internally sometimes) */
app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

/* TERRITORIES */
app.get('/api/territories', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM territories ORDER BY name ASC
    `)

    res.json(result.rows)
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed loading territories' })
  }
})

app.post('/api/territories', async (req, res) => {
  try {
    const { name, states, description } = req.body

    if (!name) {
      return res.status(400).json({ error: 'Territory name required' })
    }

    const result = await pool.query(`
      INSERT INTO territories (name, states, description)
      VALUES ($1, $2, $3)
      RETURNING *
    `, [
      name,
      states || [],
      description || ''
    ])

    res.json(result.rows[0])
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed creating territory' })
  }
})

/* TASKS */
app.post('/api/tasks', async (req, res) => {
  try {
    const {
      record_type,
      record_id,
      title,
      due_date,
      priority,
      assignee_id,
      notes
    } = req.body

    if (!record_type || !record_id || !title) {
      return res.status(400).json({ error: 'Missing required task fields' })
    }

    const result = await pool.query(`
      INSERT INTO tasks (
        record_type,
        record_id,
        title,
        due_date,
        priority,
        assignee_id,
        notes
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      RETURNING *
    `, [
      record_type,
      record_id,
      title,
      due_date || null,
      priority || 'medium',
      assignee_id || null,
      notes || ''
    ])

    res.json({ success: true, task: result.rows[0] })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Task creation failed' })
  }
})

/* NOTIFICATIONS */
app.get('/api/notifications', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM notifications
      ORDER BY created_at DESC
      LIMIT 100
    `)

    res.json(result.rows)
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Notifications failed' })
  }
})

/* ═══════════════════════════════
   STARTUP SEQUENCE (PRODUCTION SAFE)
═══════════════════════════════ */

const PORT = process.env.PORT || 10000

async function startServer() {
  try {
    console.log('🚀 Starting server...')

    await connectDB()
    await runMigrations()

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ Server running on port ${PORT}`)
    })

  } catch (err) {
    console.error('❌ Startup failed:', err)
    process.exit(1)
  }
}

startServer()
