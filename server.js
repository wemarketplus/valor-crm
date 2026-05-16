require('dotenv').config()

const express = require('express')
const cors = require('cors')
const path = require('path')
const { Pool } = require('pg')

const app = express()

/* =========================
   MIDDLEWARE
========================= */

app.use(cors())
app.use(express.json({ limit: '10mb' }))

/* =========================
   CRITICAL FIX: SERVE FRONTEND
========================= */

app.use(express.static(__dirname))

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'))
})

/* =========================
   DATABASE
========================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false
})

/* =========================
   HEALTH CHECK
========================= */

app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

/* =========================
   BASIC API SAFETY (DO NOT BREAK FRONTEND)
========================= */

app.get('/api/territories', async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM territories ORDER BY name ASC`)
    res.json(result.rows)
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'Failed loading territories' })
  }
})

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

/* =========================
   START SERVER
========================= */

const PORT = process.env.PORT || 10000

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on port ${PORT}`)
})
