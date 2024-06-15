# express-auth-mongoose
A quick way to implement a user structure to your express server. Feautring create account, login, logout, sessions and JWT

Uses a JWT regular token and not a certificate.


## Installation and usage

```
npm i express-auth-mongoose
```

To use it in your code, just add the following commands:


## ENV vars

If you intend to run this in production, you might want to change the ENV varaiables.

Mongoose?

**EXPRESS_COOKIE_AUTH_NAME**

The name of the cookie 

**EXPRESS_JWT_SECRET**

### Dependencies

This package uses some depenencies for validating input and building the Cookie and JWT

- Express - this package is intended for use with express
  - Express specific dependencies: cookie-parser, 
- Mongoose / MongoDB - If you use another DB we don't support it yet.
- Celebrate and Joi for input validation of username/password etc.
- Jsonwebtoken - For generating and validating JWT
- dotenv - For ENV files support
