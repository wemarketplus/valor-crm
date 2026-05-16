```javascript
require('dotenv').config()

const express = require('express')
const cors = require('cors')
const { Pool } = require('pg')

const app = express()

app.use(cors())
app.use(express.json({ limit: '10mb' }))

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false
})

/* ════════════════════════════════════════════════
   MIGRATIONS
════════════════════════════════════════════════ */

async function runMigrations() {

  /* TERRITORIES */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS territories (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL UNIQUE,
      states TEXT[] DEFAULT '{}',
      description TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `)

  /* WIB RECORDS */

  await pool.query(`
    ALTER TABLE wib_records
    ADD COLUMN IF NOT EXISTS territory_id UUID
    REFERENCES territories(id)
    ON DELETE SET NULL;
  `)

  /* USER PROFILES */

  await pool.query(`
    ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS territory_id UUID
    REFERENCES territories(id)
    ON DELETE SET NULL;
  `)

  /* TASKS */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      record_type TEXT NOT NULL,
      record_id UUID NOT NULL,
      title TEXT NOT NULL,
      due_date DATE,
      priority TEXT DEFAULT 'medium',
      assignee_id UUID,
      notes TEXT,
      completed BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `)

  /* NOTIFICATIONS */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID,
      title TEXT NOT NULL,
      message TEXT,
      type TEXT DEFAULT 'info',
      is_read BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `)

  /* CHAT */

  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_messages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      sender_id UUID,
      channel TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `)

  /* RELOAD CACHE */

  try {

    await pool.query(`
      SELECT pg_notify('pgrst', 'reload schema');
    `)

  } catch (err) {

    console.log('Schema reload skipped')

  }

  console.log('✅ Migrations complete')

}

/* ════════════════════════════════════════════════
   TERRITORIES API
════════════════════════════════════════════════ */

app.get('/api/territories', async (req, res) => {

  try {

    const result = await pool.query(`
      SELECT *
      FROM territories
      ORDER BY name ASC
    `)

    res.json(result.rows)

  } catch (err) {

    console.error(err)

    res.status(500).json({
      error: 'Failed loading territories'
    })

  }

})

app.post('/api/territories', async (req, res) => {

  try {

    const {
      name,
      states,
      description
    } = req.body

    if (!name) {

      return res.status(400).json({
        error: 'Territory name required'
      })

    }

    const result = await pool.query(`
      INSERT INTO territories (
        name,
        states,
        description
      )
      VALUES ($1,$2,$3)
      RETURNING *
    `, [
      name,
      states || [],
      description || ''
    ])

    res.json(result.rows[0])

  } catch (err) {

    console.error(err)

    res.status(500).json({
      error: 'Failed creating territory'
    })

  }

})

/* ════════════════════════════════════════════════
   TASKS API
════════════════════════════════════════════════ */

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

    if (
      !record_type ||
      !record_id ||
      !title
    ) {

      return res.status(400).json({
        error: 'Missing required task fields'
      })

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

    res.json({
      success: true,
      task: result.rows[0]
    })

  } catch (err) {

    console.error(err)

    res.status(500).json({
      error: 'Task creation failed'
    })

  }

})

/* ════════════════════════════════════════════════
   NOTIFICATIONS API
════════════════════════════════════════════════ */

app.get('/api/notifications', async (req, res) => {

  try {

    const result = await pool.query(`
      SELECT *
      FROM notifications
      ORDER BY created_at DESC
      LIMIT 100
    `)

    res.json(result.rows)

  } catch (err) {

    console.error(err)

    res.status(500).json({
      error: 'Notifications failed'
    })

  }

})

/* ════════════════════════════════════════════════
   HEALTH CHECK
════════════════════════════════════════════════ */

app.get('/health', (req, res) => {

  res.json({
    status: 'ok'
  })

})

/* ════════════════════════════════════════════════
   START
════════════════════════════════════════════════ */

const PORT = process.env.PORT || 3000

runMigrations()
  .then(() => {

    app.listen(PORT, () => {

      console.log(`✅ Server running on ${PORT}`)

    })

  })
  .catch(err => {

    console.error(err)
    process.exit(1)

  })
```
