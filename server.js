const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const users = require('./users');
const db = require('./database');
const app = express();
const port = process.env.PORT || 3000;

// Serve static files from the 'public' folder
app.use(express.static('public'));

// Set up session middleware
app.use(
  session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize Passport.js and set up session handling
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    const user = users.find((user) => user.email === email);

    if (!user) {
      return done(null, false, { message: 'Incorrect email.' });
    }

    try {
      if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    } catch (e) {
      return done(e);
    }
  })
);

passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await db('users').where({ id }).first();
      done(null, user);
    } catch (error) {
      done(error);
    }
  });


app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
  });
  
  // Add routes to serve login and register pages
  app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/login.html');
  });
  
  app.get('/register', (req, res) => {
    res.sendFile(__dirname + '/public/register.html');
  });

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

app.use(express.urlencoded({ extended: false }));

app.post('/register', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Check if a user with the same email already exists
      const existingUser = await db('users').where({ email }).first();
      if (existingUser) {
        return res.status(400).send('A user with this email already exists.');
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Save the new user to the database
      const [newUserId] = await db('users').insert({ email, password: hashedPassword }).returning('id');
  
      // Fetch the newly created user
      const newUser = await db('users').where({ id: newUserId }).first();
  
      // Log the user in
      req.login(newUser, (err) => {
        if (err) {
          return res.status(500).send('An error occurred during login.');
        }
        return res.redirect('/dashboard');
      });
    } catch (error) {
      console.error(error);
      res.status(500).send('An error occurred during registration.');
    }
  });
  
  
app.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login'
  }));

  function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect('/login');
  }

  app.get('/dashboard', ensureAuthenticated, (req, res) => {
    res.send('Welcome to your dashboard!');
  });

  app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/login');
  });