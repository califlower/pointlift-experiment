const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const db = require('./database');

module.exports = function (passport) {
  passport.use(
    new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
      try {
        // Find the user by email
        const user = await db('users').where({ email }).first();

        // Check if the user exists
        if (!user) {
          return done(null, false, { message: 'No user found with this email.' });
        }

        // Check if the password is correct
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          return done(null, false, { message: 'Incorrect password.' });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
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
};
