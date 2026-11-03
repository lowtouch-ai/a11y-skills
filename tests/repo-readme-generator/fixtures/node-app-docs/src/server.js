const express = require('express');
const { Pool } = require('pg');
const app = express();
const db = new Pool({ connectionString: process.env.DATABASE_URL });
const cache = process.env.REDIS_URL;
app.get('/health', (req, res) => res.json({ ok: true }));
app.get('/orders', async (req, res) => res.json((await db.query('select * from orders')).rows));
app.post('/orders', async (req, res) => res.status(201).json({}));
app.listen(process.env.PORT || 3000);
