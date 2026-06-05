# Code Examples

[Back to API index](../api.md) | [Back to docs index](../../README.md) | [Back to project README](../../../README.md)

## Code Examples

### Basic Integration

```javascript
import express from 'express';
import mbkauthe, { validateSession } from 'mbkauthe';
import dotenv from 'dotenv';

dotenv.config();

// Configure MBKAuthe
process.env.mbkautheVar = JSON.stringify({
  APP_NAME: process.env.APP_NAME,
  SESSION_SECRET_KEY: process.env.SESSION_SECRET_KEY,
  IS_DEPLOYED: process.env.IS_DEPLOYED,
  DOMAIN: process.env.DOMAIN,
  LOGIN_DB: process.env.LOGIN_DB,
  MBKAUTH_TWO_FA_ENABLE: process.env.MBKAUTH_TWO_FA_ENABLE,
  COOKIE_EXPIRE_TIME: process.env.COOKIE_EXPIRE_TIME || 2,
  loginRedirectURL: '/dashboard'
});

const app = express();

// Mount MBKAuthe routes
app.use(mbkauthe);

// Protected route
app.get('/dashboard', sessVal, (req, res) => {
  res.send(`Welcome ${req.session.user.username}!`);
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
```

---

### Role-Based Access Control

```javascript
import { sessVal, roleChk, sessRole } from 'mbkauthe';

// Method 1: Separate middleware
app.get('/admin', sessVal, roleChk('SuperAdmin'), (req, res) => {
    res.send('Admin panel');
  }
);

// Method 2: Combined middleware
app.get('/admin', sessRole('SuperAdmin'), (req, res) => {
    res.send('Admin panel');
  }
);

// Allow any role except Guest
app.get('/content', sessVal, roleChk('Any', 'Guest'), (req, res) => {
    res.send('Content for registered users');
  }
);

// Multiple roles (using separate middleware)
app.get('/moderator', sessVal, (req, res, next) => {
    if (['SuperAdmin', 'NormalUser'].includes(req.session.user.role)) {
      next();
    } else {
      res.status(403).send('Access denied');
    }
  },
  (req, res) => {
    res.send('Moderator panel');
  }
);
```

---

### API Authentication

```javascript
import { authenticate } from 'mbkauthe';

// Simple token authentication
app.post('/api/webhook',  authenticate(process.env.WEBHOOK_SECRET), (req, res) => {
    // Process webhook
    res.json({ received: true });
  }
);

// Admin API with token authentication
app.post('/api/admin/terminate-sessions', authenticate(process.env.MAIN_SECRET_TOKEN),  async (req, res) => {
    // Terminate all sessions
    res.json({ success: true });
  }
);

// Protected API endpoint (requires session)
app.get('/api/user/profile',  sessVal, async (req, res) => {
    const { username } = req.session.user;
    
    // Fetch user profile
    const profile = await getUserProfile(username);
    
    res.json({ success: true, profile });
  }
);
```

---

### Client-Side Login

```javascript
// Login form submission
document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  
  try {
    const response = await fetch('/mbkauthe/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    
    if (data.success) {
      if (data.twoFactorRequired) {
        // Redirect to 2FA page
        window.location.href = '/mbkauthe/2fa';
      } else {
        // Login successful, redirect
        window.location.href = data.redirectUrl || '/dashboard';
      }
    } else {
      alert(data.message || 'Login failed');
    }
  } catch (error) {
    console.error('Login error:', error);
    alert('An error occurred during login');
  }
});
```

---

### Client-Side Logout

```javascript
async function logout() {
  // Get CSRF token from page
  const csrfToken = document.querySelector('[name="_csrf"]').value;
  
  try {
    const response = await fetch('/mbkauthe/api/logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ _csrf: csrfToken })
    });
    
    const data = await response.json();
    
    if (data.success) {
      window.location.href = '/mbkauthe/login';
    } else {
      alert('Logout failed: ' + data.message);
    }
  } catch (error) {
    console.error('Logout error:', error);
  }
}
```

---

### Database Access

```javascript
import { dblogin } from 'mbkauthe';

// Custom query using the database pool
app.get('/api/users', sessVal, roleChk('SuperAdmin'), async (req, res) => {
  try {
    const result = await dblogin.query(
      'SELECT id, "UserName", "Role", "Active" FROM "Users" ORDER BY id'
    );
    
    res.json({ 
      success: true, 
      users: result.rows 
    });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal Server Error' 
    });
  }
});
```

---

### Error Handling

```javascript
// Custom error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ 
      success: false, 
      message: 'Invalid CSRF token' 
    });
  }
  
  res.status(500).json({ 
    success: false, 
    message: 'Internal Server Error' 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('Error/dError.handlebars', {
    layout: false,
    code: 404,
    error: 'Not Found',
    message: 'The requested page was not found.',
    pagename: 'Home',
    page: '/',
  });
});
```

---

