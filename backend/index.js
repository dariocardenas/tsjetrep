const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();

// Keep it simple: accept CSV as plain text in POST body.
app.use(
  cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
    methods: ['POST', 'OPTIONS'],
  })
);
app.options('*', cors());
app.use(express.text({ type: ['text/*', 'application/csv', 'text/csv'], limit: '5mb' }));

const BCRYPT_COST = 10;

function parseUsersCsv(csvText) {
  const lines = String(csvText)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  // Always skip the first non-empty line (treat as header).
  const dataLines = lines.slice(1);

  return dataLines.map((line) => {
    const idx = line.indexOf(',');
    if (idx === -1) {
      throw new Error(`Invalid CSV line (missing comma): ${line}`);
    }
    const user = line.slice(0, idx).trim();
    const password = line.slice(idx + 1).trim();
    if (!user || !password) {
      throw new Error(`Invalid CSV line (empty user/password): ${line}`);
    }
    return { user, password };
  });
}

app.post('/hashcsv', async (req, res) => {
  try {
    const cost = Number(req.query.cost ?? BCRYPT_COST);
    if (!Number.isInteger(cost) || cost < 4 || cost > 15) {
      return res.status(400).json({ error: 'Invalid cost; expected integer between 4 and 15.' });
    }

    const rows = parseUsersCsv(req.body);

    const out = await Promise.all(
      rows.map(async ({ user, password }) => {
        const hash = await bcrypt.hash(password, cost);
        // pfSense expects $2b$ prefix (native bcrypt already emits $2b$ on modern builds)
        return { user, password: hash };
      })
    );

    res.json(out);
  } catch (err) {
    res.status(400).json({ error: err?.message ?? String(err) });
  }
});

const port = Number(process.env.PORT ?? 8787);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`tsjetrep backend listening on http://localhost:${port}`);
});

