# JWT Authentication Demo (Node.js, Express, Vanilla JS)

A secure starter project demonstrating **JWT authentication**, **role-based authorization**, **refresh tokens**, and modern security best practices using Node.js, Express.js, and a vanilla JS/HTML/CSS frontend.

---

## Features

- Signup, Login, and Logout flows
- JWT stored in HttpOnly, Secure, SameSite cookies
- Refresh token support for seamless session extension
- Role-based access control (user/admin)
- Secure password hashing (bcrypt)
- Input validation, rate limiting, CSRF and XSS protection
- Demo user storage in `users.json` (swap for real DB easily)

---

## Project Structure

jwt-auth-demo/
├── .env
├── package.json
├── server.js
├── users.json
├── public/
│ ├── login.html
│ ├── signup.html
│ ├── dashboard.html
│ ├── styles.css
│ └── main.js
└── ...


---

## Getting Started

1. **Clone the repo**

    ```bash
    git clone https://github.com/your-repo/jwt-auth-demo.git
    cd jwt-auth-demo
    ```

2. **Install dependencies**

    ```bash
    npm install
    ```

3. **Create a `.env` file**

    See the `.env` sample below.

4. **Start the server**

    ```bash
    npm start
    # or
    node server.js
    ```

5. **Visit** [http://localhost:3000](http://localhost:3000)

---

##  .env Sample

```env
JWT_SECRET=your_super_long_random_access_token_secret_here
JWT_REFRESH_SECRET=your_super_long_random_refresh_token_secret_here
NODE_ENV=development
PORT=3000
```

 ## Usage

- Signup: Go to /signup.html and create a new user.
- Login: Go to /login.html, log in.
- Dashboard: Access /dashboard.html (protected route).
- Admin route: (If your user has "role": "admin" in users.json), you can hit /api/admin.
- Logout: Use the "Logout" button on the dashboard.

## Security Best Practices Used

- Secure JWT cookies. (HttpOnly, Secure, SameSite)
- CSRF protection using tokens and double-submit pattern.
- Rate limiting on sensitive routes (e.g., login).
- Passwords stored using bcrypt hash.
- Helmet for HTTP header hardening.
- Input validation and centralized error handling.
- Role-based access middleware.

## Extending for Production

- Swap users.json for a real database (PostgreSQL, MongoDB, etc.)
- Implement real email verification and password reset (see server.js stubs)
- Add logging, monitoring, and CORS policies as needed
- Enforce HTTPS everywhere (NODE_ENV=production for secure cookies)

## License
MIT