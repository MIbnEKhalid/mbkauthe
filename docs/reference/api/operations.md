# Operational Reference

[Back to API index](../api.md) | [Back to docs index](../../README.md) | [Back to project README](../../../README.md)

## Error Codes

### HTTP Status Codes

| Code | Meaning | Usage |
|------|---------|-------|
| 200 | OK | Successful request |
| 400 | Bad Request | Invalid input data |
| 401 | Unauthorized | Authentication required or failed |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server-side error |

---

## Security Best Practices

1. **Always use HTTPS in production** - Set `IS_DEPLOYED=true` and ensure your server uses SSL/TLS
2. **Keep SESSION_SECRET_KEY secure** - Use a strong, randomly generated key
3. **Enable 2FA for sensitive applications** - Set `MBKAUTH_TWO_FA_ENABLE=true`
4. **Validate all user input** - Never trust client-side data
5. **Use rate limiting** - Already implemented for authentication endpoints
6. **Keep dependencies updated** - Regularly update npm packages
7. **Monitor for security vulnerabilities** - Use `npm audit`
8. **Use prepared statements** - Prevent SQL injection (already implemented)
9. **Implement proper logging** - Track authentication events
10. **Regular security audits** - Review code and configurations

---

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/mbkauthe/api/login` | 8 requests | 1 minute |
| `/mbkauthe/api/logout` | 10 requests | 1 minute |
| `/mbkauthe/api/verify-2fa` | 5 requests | 1 minute |
| `/mbkauthe/api/github/login` | 10 requests | 5 minutes |
| `/mbkauthe/api/github/login/callback` | 10 requests | 5 minutes |
| `/mbkauthe/login` | 8 requests | 1 minute |
| `/mbkauthe/info` | 8 requests | 1 minute |
| `/mbkauthe/test` | 8 requests | 1 minute |

Rate limits are applied per IP address. Logged-in users are exempt from some rate limits (e.g., login page rate limit).

---

