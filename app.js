//------------------------------------------- Siladitya Samaddar -------------------------------------------------------//
//
// bcrypt, node-module is used to encrypt password.
// bcrypt salt and hash used.
//
//-----------------------------------------------------------------------------------------------------------------------//

//.............. imports ............
require("dotenv").config();

const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

//........................... constants ..............................
const saltRounds = 10;

//........................... app setup ..............................
const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

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
const User = new mongoose.model("User", userSchema);

//.............................. routes ..................................
app.get("/", (req, res) => res.render("home"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  //bcrypt hash passowrd
  bcrypt.hash(password, saltRounds, (err, hash) => {
    const newUser = new User({
      email: username,
      password: hash,
    });
    newUser.save((err) => (err ? console.log(err) : res.render("secrets")));
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  User.findOne({ email: username }, (err, foundUser) => {
    if (err) console.log(err);
    else if (foundUser) {
      //bcrypt compare hash password
      bcrypt.compare(password, foundUser.password, (err, result) => {
        if (result) res.render("secrets");
      });
    }
  });
});

//................................ listen ...................................s
app.listen(3000, () => {
  console.log("Server is ruuning at port 3000");
});
