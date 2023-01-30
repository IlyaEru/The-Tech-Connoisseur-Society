import express from 'express';
import helmet from 'helmet';
const xss = require('xss-clean');
import ExpressMongoSanitize from 'express-mongo-sanitize';
import compression from 'compression';
import cors from 'cors';
import passport from 'passport';
import dotenv from 'dotenv';

import MongoStore from 'connect-mongo';

import localStrategy from 'passport-local';
import session from 'express-session';
import flash from 'express-flash';
import bcrypt from 'bcryptjs';

import routes from './routes';

import User from './components/user/user.model';
import { UserType } from './components/user/user.type';

const app = express();

// load env vars
dotenv.config();

// set security HTTP headers
app.use(helmet());

// enable cors
app.use(cors());
app.options('*', cors());

// parse json request body
app.use(express.json());

// parse urlencoded request body
app.use(express.urlencoded({ extended: true }));

// sanitize request data
app.use(xss());
app.use(ExpressMongoSanitize());

// gzip compression
app.use(compression());

app.set('view engine', 'ejs');
app.set('views', 'src/views');

app.use(express.static('public'));

// set port, listen for requests

const port = process.env.PORT || 3000;

// passport config
const LocalStrategy = localStrategy.Strategy;
app.use(
  session({
    secret: process.env.SESSION_SECRET as string,
    resave: false,
    saveUninitialized: false,
    // store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }), //  large speed impact
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
    },
  }),
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err: any, user: UserType) => {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, {
          message: 'Username or Password are incorrect',
        });
      }
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user);
        } else {
          // passwords do not match!
          return done(null, false, {
            message: 'Username or Password are incorrect',
          });
        }
      });
    });
  }),
);

passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser((id: any, done) => {
  User.findById(id, (err: any, user: any) => {
    done(err, user);
  });
});

app.use((req, res, next) => {
  res.locals.isLoggedIn = req.isAuthenticated();
  res.locals.user = req.user;
  res.locals.isUserAdmin = req.user?.admin;
  res.locals.isUserMember = req.user?.member;
  res.locals.path = req.path;
  next();
});

app.use(routes);

app.use((req, res) => {
  res.status(404).render('404', { pageTitle: '404' });
});

export default app;
