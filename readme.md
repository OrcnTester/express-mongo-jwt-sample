
// =============================
// File: README.md
// =============================
# Express + Mongo + JWT — Mini Challenge Solution

A minimal, interview-ready API showcasing registration/login, protected routes, and pagination.

## Endpoints
- `GET /health` → quick health check.
- `POST /auth/register` → { email, name, password } → returns JWT + user.
- `POST /auth/login` → { email, password } → returns JWT + user.
- `POST /users` (auth) → create another user.
- `GET /users/:id` (auth)
- `GET /users?page=1&limit=10` (auth) → pagination.

## Run locally
```bash
cp .env.example .env
npm i
npm run dev
```
Open http://localhost:3000/health

## Quick test (HTTPie or curl)
```bash
# register
http POST :3000/auth/register email=demo@demo.io name=Demo password=secret12

# login
http POST :3000/auth/login email=demo@demo.io password=secret12
# copy the token from response

# create a user
http POST :3000/users \
  Authorization:"Bearer <TOKEN>" \
  email=second@demo.io name=Second password=secret12 role=user

# list users
http GET :3000/users Authorization:"Bearer <TOKEN>" page==1 limit==5

# get by id
http GET :3000/users/<ID> Authorization:"Bearer <TOKEN>"
```

## Notes
- Uses **Zod** for validation, **bcrypt** for password hashing, **JWT** for auth.
- Keeps handlers small & readable; centralized error handling.
- Easy to extend with roles/permissions and rate-limiting.
\n\n> Demo: Access+Refresh JWT rotation implemented ✅
