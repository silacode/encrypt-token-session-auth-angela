//------------------------------------------- Siladitya Samaddar -------------------------------------------------------//
//
// passport google and local strategy for cookie based session authorization
// authenticated routes
//
//
//-----------------------------------------------------------------------------------------------------------------------//

//.............. imports ............
require("dotenv").config();

const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
//also install passport-local

//........................... constants ..............................
const secret = process.env.SECRET;
const PORT = 4000;

//........................... app setup ..............................
const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
//express-session cookie setup
app.use(
  session({
    secret: secret,
    resave: false,
    saveUninitialized: false,
  })
);
// passport initialization and setup for cookie session
app.use(passport.initialize());
app.use(passport.session());

//.......................... database setup ...........................
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});
const db = mongoose.connection;
db.on("connected", () => console.log("Connected to mongoDb atlas"));
db.on("error", (err) => console.log("Failed to connect to mongoDb atlas", err));
db.on("disconnected", () => console.log("MongoDB event disconnected"));
process.on("SIGINT", () => {
  db.close(() => {
    console.log(
      "Mongoose connection is disconnected due to application termination"
    );
    process.exit(0);
  });
});

//............................. database schema ..........................
const Schema = mongoose.Schema;
const userSchema = new Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});
//passport-local-mongoose is used to hash and salt password and save to database
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);

//.............................. passport setup .............................
//passport local login strategy
passport.use(User.createStrategy());
//serialize and deserialize user into cookie
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) =>
  User.findById(id, (err, user) => done(err, user))
);
//google strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:4000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    (accessToken, refreshToken, profile, cb) =>
      //google login register both logic
      User.findOrCreate({ googleId: profile.id }, (err, user) => {
        return cb(err, user);
      })
  )
);

//.............................. routes ..................................
app.get("/", (req, res) => res.render("home"));

//google authentication route
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  // Successful authentication, redirect secrets.
  (req, res) => res.redirect("/secrets")
);
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

app.get("/secrets", (req, res) => {
  User.find({ secret: { $ne: null } }, (err, foundUsers) => {
    if (err) console.log(err);
    else if (foundUsers)
      res.render("secrets", { usersWithSecrets: foundUsers });
  });
});

//authenticated get submit route
// req.isAuthenticated() method is used to check if logged in or not
app.get("/submit", (req, res) => {
  req.isAuthenticated() ? res.render("submit") : res.redirect("/login");
});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;
  User.findById(req.user.id, (err, foundUser) => {
    if (err) console.log(err);
    else if (foundUser) {
      foundUser.secret = submittedSecret;
      foundUser.save(() => res.redirect("/secrets"));
    }
  });
});

//logout route
app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

//register route local strategy
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  //passport method for register
  User.register({ username }, password, (err, user) => {
    if (err) {
      console.log(err);
      res.redirect("/register");
    }
    passport.authenticate("local")(req, res, () => res.redirect("/secrets"));
  });
});

//login route local strategy
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = new User({ username, password });
  //passport method for login
  req.login(user, (err) => {
    if (err) console.log(err);
    passport.authenticate("local")(req, res, () => res.redirect("/secrets"));
  });
});

//................................ listen ...................................s
app.listen(PORT, () => {
  console.log(`Server is ruuning at port ${PORT}`);
});
