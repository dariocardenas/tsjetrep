## tsjetrep backend

Simple bcrypt hashing service used by the frontend.

### Run

```bash
cd backend
npm install
npm run start
```

By default it listens on `http://localhost:8787`.

### Endpoint

`POST /hashcsv` (body: raw CSV text)

CSV format:

```text
user,password
ctx1,VL3aW&4TkPK8HIF
ctx2,123qwe
```

Response:

```json
[{ "user": "ctx1", "password": "$2b$10$..." }]
```

Quick test:

```bash
curl -sS -X POST "http://localhost:8787/hashcsv" \
  -H "content-type: text/csv" \
  --data-binary $'user,password\nctx1,123qwe\n' | jq .
```

