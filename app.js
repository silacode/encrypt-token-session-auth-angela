//------------------------------------------- Siladitya Samaddar -------------------------------------------------------//
//
// passport local strategy for cookie based session authorization
// authenticated routes
// passport, passport-local, passport-local-mongoose, express-session modules are used.
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
//also install passport-local

//........................... constants ..............................
const secret = process.env.SECRET;

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
});
//passport-local-mongoose is used to hash and salt password and save to database
userSchema.plugin(passportLocalMongoose);
const User = new mongoose.model("User", userSchema);

//.............................. passport setup .............................
//passport local login strategy
passport.use(User.createStrategy());
//serialize and deserialize user into cookie
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//.............................. routes ..................................
app.get("/", (req, res) => res.render("home"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));
//authenticated route
app.get("/secrets", (req, res) => {
  req.isAuthenticated() ? res.render("secrets") : res.redirect("/login");
});
app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});
//register route
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
//login route
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
app.listen(3000, () => {
  console.log("Server is ruuning at port 3000");
});
