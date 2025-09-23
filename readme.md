<p align="center">
  <a href="https://github.com/OrcnTester/express-mongo-jwt-sample">
    <img alt="Stars" src="https://img.shields.io/github/stars/OrcnTester/express-mongo-jwt-sample?style=flat-square">
  </a>
  <a href="https://github.com/OrcnTester/express-mongo-jwt-sample/issues">
    <img alt="Issues" src="https://img.shields.io/github/issues/OrcnTester/express-mongo-jwt-sample?style=flat-square">
  </a>
  <img alt="Last commit" src="https://img.shields.io/github/last-commit/OrcnTester/express-mongo-jwt-sample?style=flat-square">
  <img alt="Node" src="https://img.shields.io/badge/node-20.x-339933?logo=node.js&logoColor=white&style=flat-square">
  <img alt="Express" src="https://img.shields.io/badge/express-4.x-black?logo=express&logoColor=white&style=flat-square">
  <img alt="MongoDB" src="https://img.shields.io/badge/mongodb-6.x-47A248?logo=mongodb&logoColor=white&style=flat-square">
  <img alt="JWT" src="https://img.shields.io/badge/JWT-auth-000000?logo=jsonwebtokens&logoColor=white&style=flat-square">
  <img alt="Zod" src="https://img.shields.io/badge/zod-validation-3E67B1?style=flat-square">
  <img alt="Docker" src="https://img.shields.io/badge/docker-ready-0db7ed?logo=docker&logoColor=white&style=flat-square">
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
  </a>
  <img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square">
</p>


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
\n> Includes access+refresh JWT rotation with TTL-backed blacklist.
