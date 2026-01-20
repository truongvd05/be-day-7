## Environment Setup

Create a `.env` file based on `.env.example` and update the values.

<API Endpoints>

<Register>
POST /api/auth/register
Body {
  "email": "user@example.com",
  "password": "123456"
}

<Login>
POST /api/auth/login 
Body {
  "email": "user@example.com",
  "password": "123456"
}

<refresh-token>
POST /api/auth/refresh-toke
body {
  "refresh_token: "mnmnkllknluoiuoutryeerrrsas"
}
