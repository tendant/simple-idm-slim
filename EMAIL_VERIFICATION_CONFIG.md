# Email Verification Configuration

Email verification enforcement is now **configurable** via environment variable.

## Configuration

Add to your `.env` file:

```bash
# Email Verification Enforcement (optional, default: true)
# Set to false to allow login without email verification
REQUIRE_EMAIL_VERIFICATION=false
```

## Behavior

### When `REQUIRE_EMAIL_VERIFICATION=true` (default)
- Users MUST verify their email before they can login
- Login attempts with unverified email return HTTP 403:
  ```json
  {
    "error": "email verification required. Please check your email for verification link"
  }
  ```
- This is the **recommended setting for production**

### When `REQUIRE_EMAIL_VERIFICATION=false`
- Users can login immediately after registration
- Email verification is optional
- Useful for:
  - **Testing/Development** - Skip email verification during development
  - **Internal Systems** - When email verification isn't needed
  - **Gradual Rollout** - Allow unverified users initially

## How It Works

1. **Registration** - Always succeeds, user created with `email_verified=false`
2. **Login** - Behavior depends on configuration:
   - `true` → Checks `user.email_verified`, blocks if false
   - `false` → Skips email verification check, allows login

3. **JWT Token** - Always includes `email_verified` claim:
   ```json
   {
     "sub": "user_id",
     "email": "user@example.com",
     "email_verified": false,  // ← Always present
     "tenant_id": "uuid",
     "membership_id": "uuid"
   }
   ```

4. **Application Logic** - Your app can still check `email_verified` in the JWT:
   ```go
   claims := middleware.GetClaims(r.Context())
   if !claims.EmailVerified {
       // Show verification reminder
   }
   ```

## Example Use Cases

### Development/Testing
```bash
# .env
REQUIRE_EMAIL_VERIFICATION=false  # Skip verification for faster testing
SMTP_HOST=                        # No email service needed
```

### Production
```bash
# .env
REQUIRE_EMAIL_VERIFICATION=true   # Enforce verification
SMTP_HOST=smtp.sendgrid.net       # Email service configured
SMTP_USER=apikey
SMTP_PASSWORD=your_sendgrid_key
```

### Hybrid (Optional Verification)
```bash
# .env
REQUIRE_EMAIL_VERIFICATION=false   # Allow unverified users
SMTP_HOST=smtp.sendgrid.net        # But still send verification emails
```

In this mode:
- Users can login immediately
- Verification emails are still sent
- Your app can encourage verification with UI prompts
- JWT includes `email_verified` status for app-level decisions

## Migration Guide

If upgrading from a version that always required verification:

1. **Default Behavior** - No change needed, defaults to `true`
2. **Disable Verification** - Add `REQUIRE_EMAIL_VERIFICATION=false` to `.env`
3. **No Code Changes** - Configuration only, no code modifications needed

## Test Results

✅ **With `REQUIRE_EMAIL_VERIFICATION=false`:**
- Registration: ✓ Success
- Login (unverified): ✓ Success
- Protected endpoints: ✓ Accessible
- JWT contains: `email_verified: false`

✅ **With `REQUIRE_EMAIL_VERIFICATION=true`:**
- Registration: ✓ Success
- Login (unverified): ✗ Blocked (HTTP 403)
- Error message: "email verification required..."
- Must verify email before login

## API Impact

No breaking changes to API endpoints:

- `POST /v1/auth/password/register` - Unchanged
- `POST /v1/auth/password/login` - Unchanged (behavior configurable)
- `POST /v1/auth/verify-email` - Still available for verification
- `GET /v1/me` - Includes `email_verified` field

## Security Considerations

### When to Use `true` (Enforced)
- ✅ Public-facing applications
- ✅ When email is used for password recovery
- ✅ When email ownership must be proven
- ✅ Compliance requirements

### When to Use `false` (Optional)
- ✅ Internal applications with SSO
- ✅ Development/testing environments
- ✅ Applications with alternative verification methods
- ✅ Gradual rollout of email verification

**Note:** Even with enforcement disabled, your application can still implement custom verification logic using the `email_verified` claim in the JWT.
