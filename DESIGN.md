---
title: "simple-idm v0: Minimal Password + Google OAuth"
project: "tendant/simple-idm"
version: "v0.1"
date: "2026-01-20"
status: "Proposed"
---

# Goals

Build the smallest reliable identity service that supports:

- Email + password login
- Google OAuth login
- A single session/token model shared by both login methods
- A clean extension point for **2FA later** (without implementing it now)

Non-goals (explicitly out of scope for v0):

- Multi-tenancy / organizations
- RBAC / permissions / groups / scopes
- Magic links / passwordless
- OAuth authorization server features (issuing codes for third-party clients)
- Device fingerprinting / trusted devices
- Account recovery beyond basic password reset (optional)
- Admin UI

---

# High-level architecture

## Components

- **simple-idm** (HTTP API)
  - Auth endpoints (password + Google OAuth)
  - Session issuing + revocation
  - Minimal user profile
- **PostgreSQL**
  - Stores users, credentials, identities, sessions
- **Optional: Email sender**
  - Only if you choose password reset / email verification

## Data flow

1. User authenticates via password or Google OAuth
2. Server resolves a `user_id`
3. Server issues a session (cookie or refresh token)
4. Client uses session to access protected endpoints (`/v1/me`, etc.)

---

# Core domain model (minimal schema)

This schema is designed to be **data-compatible** with richer schemas while staying minimal.

## users

Represents the account.

**Fields**
- `id` (uuid, pk)
- `email` (citext, unique)
- `email_verified` (bool, default false)
- `name` (text, nullable)
- `created_at`, `updated_at`
- `deleted_at` (nullable) — optional soft delete

## user_password

Separates password credentials from the user profile.

**Fields**
- `user_id` (uuid, pk/fk -> users.id)
- `password_hash` (text) — Argon2id recommended
- `password_updated_at` (timestamptz)

Notes:
- You can preserve existing hashes during migration.
- You can “rehash on login” later if you want to standardize.

## user_identities

Stores external identities (Google now; other providers later if needed).

**Fields**
- `id` (uuid, pk)
- `user_id` (uuid, fk -> users.id)
- `provider` (text) — e.g. `google`
- `provider_subject` (text) — stable provider user id (Google `sub`)
- `email` (text, nullable) — copy of claim for convenience
- `created_at` (timestamptz)

**Constraints**
- Unique `(provider, provider_subject)`

## sessions (or refresh_tokens)

A single session model shared by both password and Google login.

**Fields**
- `id` (uuid, pk)
- `user_id` (uuid, fk -> users.id)
- `token_hash` (bytea/text) — store a hash, not the raw token
- `created_at` (timestamptz)
- `expires_at` (timestamptz)
- `revoked_at` (timestamptz, nullable)
- `last_seen_at` (timestamptz, nullable)
- `metadata` (jsonb, nullable) — optional (ip/user-agent), keep minimal

Notes:
- Access tokens may be short-lived JWTs with refresh tokens stored here, OR
- This table itself can represent sessions (opaque tokens) for web.

---

# Authentication methods

## Password authentication

### Register (optional)
- `POST /v1/auth/password/register`
- Creates a user + password credential.
- In v0, you may skip registration and use “invite-only” provisioning.

### Login
- `POST /v1/auth/password/login`
- Verifies password hash.
- Issues a session.

### Password reset (optional)
If you want minimal complexity, keep password reset out of v0.
If you include it:
- `POST /v1/auth/password/reset/start` (email a link)
- `POST /v1/auth/password/reset/finish` (token + new password)

---

## Google OAuth authentication

Two endpoints:

### Start
- `GET /v1/auth/google/start?redirect_uri=<app_return_uri>`
- Creates state + nonce (stored server-side or signed).
- Redirects to Google consent screen.

### Callback
- `GET /v1/auth/google/callback?code=...&state=...`
- Exchanges code for tokens
- Validates ID token (issuer/audience/nonce)
- Extracts claims (`sub`, `email`, `email_verified`, `name`)

### Account resolution rules (safe defaults)

1. If `(provider='google', provider_subject=sub)` exists → use linked user
2. Else if `email` matches an existing user AND `email_verified=true` on Google claim:
   - Link identity to that user **only if you want auto-linking**
   - Safer alternative: create a new user and require explicit linking later
3. Else create new user and link identity

Then issue a session.

---

# Session model

Pick one model for v0 to avoid complexity.

## Option A: Cookie session (best for web)

- Server issues an opaque token stored in cookie (HttpOnly, Secure, SameSite)
- DB stores `token_hash`
- API uses cookie middleware to authenticate requests

Pros: simplest for web  
Cons: mobile clients may prefer bearer tokens

## Option B: Refresh token + access token (best for web + mobile)

- Server issues:
  - short-lived access token (JWT)
  - long-lived refresh token (opaque, stored hashed in DB)
- Client sends access token as `Authorization: Bearer ...`
- Refresh endpoint rotates refresh token (optional)

Pros: supports mobile and web cleanly  
Cons: slightly more moving parts

**Recommended for your stated web+mobile direction:** Option B.

---

# Minimal API surface

## Public auth endpoints

- `POST /v1/auth/password/login`
- `POST /v1/auth/password/register` (optional)
- `GET  /v1/auth/google/start`
- `GET  /v1/auth/google/callback`
- `POST /v1/auth/logout`
- `POST /v1/auth/refresh` (if using refresh tokens)

## Protected endpoints

- `GET /v1/me` — returns user profile (id, email, name, email_verified)

---

# Future 2FA without redesign (hook points)

Do **not** implement 2FA now. Just keep a clean place to add it.

## Concept: gated session issuance

Introduce a single service function:

- `IssueSession(userID, opts)`

Later you add:
- `opts.RequireMFA = true`
- or a user-level policy check: `if user has 2FA enabled -> gate`

## Later tables (not in v0)

- `mfa_settings(user_id, enabled, type, created_at)`
- `totp_secrets(user_id, encrypted_secret, created_at)` or `webauthn_credentials`
- `auth_challenges(id, user_id, kind, expires_at, consumed_at, metadata)`

2FA becomes a second step after primary auth:
1. Password/Google proves identity → create an auth challenge
2. Verify OTP/WebAuthn → issue normal session

---

# Migration plan from current simple-idm schema

Goal: migrate accounts safely while deleting unused complexity.

## Approach: Expand → Backfill → Switch reads → Cleanup

### 1) Expand
- Add new tables (`user_password`, `user_identities`, `sessions`) alongside existing tables.
- Do not delete anything yet.

### 2) Backfill
- Backfill `user_password` from existing password data (current hash only).
- Backfill `user_identities` for Google users:
  - Prefer provider stable id (`sub`) if present
  - Else store email and link on next login (capture `sub` then)
- Optionally create new sessions table and force re-login (acceptable).

### 3) Switch reads
Update application code so:

- Password login reads from `user_password`
- Google login reads from `user_identities`
- Session middleware reads from `sessions`

### 4) Cleanup (after a bake period)
Once stable, remove unused tables and code paths:

- 2FA: `login_2fa`, `backup_codes`
- magic links: `login_magic_link_tokens`
- device tracking: `device`, `login_device`, `login_attempt`
- oauth server: `oauth2_clients`, `oauth2_client_scopes`, `oauth2_client_redirect_uris`
- rbac: `roles`, `groups`, `scopes`, `user_roles`, `user_groups`
- password history/reset tables if not used

Keep an archive if you want (rename to `_legacy_*`).

---


## Feature modules vs shared core

Use **feature modules at the HTTP layer**, with a shared core underneath. This keeps v0 simple while making future features (like 2FA) easy to add or remove.

### Where to use feature modules
Use dedicated modules when a feature has:
- Its own HTTP routes
- Its own request/response DTOs
- Clear boundaries that may change independently

In `simple-idm v0`, this applies to:
- Password authentication
- Google OAuth
- Session lifecycle (refresh / logout)
- User self-profile (`/me`)

### Where NOT to use feature modules
Do **not** split the following into per-feature modules:
- Domain models
- Repositories (database access)
- Crypto primitives (password hashing, token verification)
- Session issuing logic

These should remain shared to avoid duplication and over‑abstraction.

---

## Recommended module layout

```
internal/
  http/
    router.go
    middleware/
      auth.go
      logging.go
    features/
      password/
        handler.go
        routes.go
      google/
        handler.go
        routes.go
      session/
        handler.go
        routes.go
      me/
        handler.go
        routes.go

  auth/
    password.go        // hash + verify
    google.go          // id token validation
    session.go         // IssueSession, RevokeSession

  repository/
    db.go              // *sql.DB wiring, tx helper
    users_repo.go
    credentials_repo.go
    identities_repo.go
    sessions_repo.go

  domain/
    user.go
    session.go
    errors.go
```

### Design principles
- **Feature modules depend on shared core**, never the other way around
- **Repositories are capability-based**, not feature-based
- **One auth pipeline**: all features resolve `user_id` → `IssueSession`
- Adding 2FA later becomes adding a new feature module + a gate in `IssueSession`


# Implementation notes (Go)


## Repository pattern (direct SQL)

Use a small, explicit repository layer with hand-written SQL. Keep interfaces tight and avoid generic abstractions.

Recommended structure:

- `internal/repository/db.go` — `*sql.DB` wiring, tx helper
- `internal/repository/users_repo.go` — user CRUD + lookups
- `internal/repository/credentials_repo.go` — password credential read/write
- `internal/repository/identities_repo.go` — google identity lookups + link
- `internal/repository/sessions_repo.go` — issue/revoke/lookup sessions

Guidelines:
- Prefer **explicit methods** (e.g., `GetUserByEmail`, `UpsertGoogleIdentity`) over “query builders”.
- Keep SQL close to the method, with `context.Context` and prepared statements where useful.
- Use transactions only around multi-step invariants (e.g., create user + link identity).


Suggested repo layout:

- `cmd/simple-idm/` — main
- `internal/http/` — handlers + middleware
- `internal/auth/` — password verify, google oauth, session issuing
- `internal/repository/` — direct SQL (Postgres)
- `internal/domain/` — domain types

Key simplification: **one auth pipeline**
- `AuthenticateWithPassword(...) -> userID`
- `AuthenticateWithGoogle(...) -> userID`
- `IssueSession(userID) -> tokens/session`

Everything funnels into `IssueSession`.

---

# Security defaults (minimal but solid)

- Password hashing: Argon2id (with sane parameters)
- Rate-limit login attempts (even simple IP-based limiter is fine)
- Store only hashed session/refresh tokens
- Use TLS everywhere
- Set secure cookie flags if using cookie sessions
- Validate Google ID token strictly (issuer/audience/nonce)

---

# Open decisions (v0)

1. Session model:
   - Cookie session vs refresh token + access token
2. Registration:
   - Open registration vs invite-only vs admin provision
3. Email features:
   - No email in v0 (simplest) vs minimal password reset

---

# Appendix: Suggested SQL (sketch)

> This is a sketch; adjust types/indexes for your conventions.

```sql
create table if not exists users (
  id uuid primary key,
  email citext not null unique,
  email_verified boolean not null default false,
  name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz
);

create table if not exists user_password (
  user_id uuid primary key references users(id) on delete cascade,
  password_hash text not null,
  password_updated_at timestamptz not null default now()
);

create table if not exists user_identities (
  id uuid primary key,
  user_id uuid not null references users(id) on delete cascade,
  provider text not null,
  provider_subject text not null,
  email text,
  created_at timestamptz not null default now(),
  unique(provider, provider_subject)
);

create table if not exists sessions (
  id uuid primary key,
  user_id uuid not null references users(id) on delete cascade,
  token_hash text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  last_seen_at timestamptz,
  metadata jsonb
);
```

