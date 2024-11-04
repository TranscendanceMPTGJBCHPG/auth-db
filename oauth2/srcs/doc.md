# OAuth + 2FA Authentication System

## Authentication Flow

1. User initiates OAuth login with 42
2. First login:
   - System generates 2FA secret
   - Returns QR code for Google Authenticator setup
3. Subsequent logins:
   - System requires 2FA code
   - Returns JWT on successful verification

## API Endpoints

### OAuth Login
`POST /auth/oauth/`

#### First Login Request
```bash
curl -X POST http://localhost:8080/auth/oauth/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "code=YOUR_OAUTH_CODE"
```

Response:
```json
{
    "status": "setup_2fa",
    "qr_code": "BASE64_QR_CODE",
    "message": "Please set up Google Authenticator with the provided QR code"
}
```

#### Subsequent Login Request
```bash
curl -X POST http://localhost:8080/auth/oauth/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "code=YOUR_OAUTH_CODE" \
  -d "totp_token=2FA_CODE"
```

Success Response:
```json
{
    "access_token": "JWT_TOKEN"
}
```

Error Response:
```json
{
    "error": "Error message"
}
```

## Response Status Codes

- `200`: Success (JWT provided)
- `400`: Bad Request (Invalid code/token)
- `500`: Server Error

## JWT Token Structure

```json
{
    "username": "user_login",
    "email": "user_email",
    "game_access": 1,
    "image_link": "user_image_url",
    "exp": "expiration_timestamp"
}
```

## Testing

```bash
# Test new user flow
curl -X POST http://localhost:8080/auth/oauth/ \
  -d "code=YOUR_OAUTH_CODE"

# Test existing user with 2FA
curl -X POST http://localhost:8080/auth/oauth/ \
  -d "code=YOUR_OAUTH_CODE" \
  -d "totp_token=2FA_CODE"
```

## Error Handling

- Missing OAuth code: `{"error": "Failed: No code provided"}`
- Invalid 2FA code: `{"error": "Invalid 2FA code"}`
- API failures: `{"error": "API request failed"}`