const express = require("express");
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");
var nodemailer = require('nodemailer');
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
require("dotenv").config();
const app = express();
const bodyParser = require("body-parser");

var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD
    }
});



const PORT = process.env.PORT || 3000;

const initializePassport = require("./passportConfig");

initializePassport(passport);

// Middleware

// Parses details from a form
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.use(express.static(__dirname + '/views'));
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(bodyParser.json());

app.use(
  session({
    // Key we want to keep secret which will encrypt all of our information
    secret: process.env.SESSION_SECRET,
    // Should we resave our session variables if nothing has changes which we dont
    resave: false,
    // Save empty value if there is no vaue which we do not want to do
    saveUninitialized: false
  })
);
// Funtion inside passport which initializes passport
app.use(passport.initialize());
// Store our variables to be persisted across the whole session. Works with app.use(Session) above
app.use(passport.session());
app.use(flash());

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/users/register", checkAuthenticated, (req, res) => {
  res.render("register.ejs");
});


app.get("/users/login", checkAuthenticated, (req, res) => {
  // flash sets a messages variable. passport sets the error message
  // console.log(req.session.flash.error);
  res.render("login.ejs");
});

app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user });
});

app.get("/users_list", checkNotAuthenticated, (req, res) => {
  res.render("users_list", { user: req.user });
});

app.get("/users_list/:start", checkNotAuthenticated, (req, res) => {
  var start = parseInt(req.params.start*8) + 22;
  pool.query(
    `SELECT * FROM users
    WHERE id > $1 and id < $2`,
    [start,start+8],
    (err, results) => {
      if (err) {
        throw err;
      }
      res.send({ users: results.rows});
    }
  );  
});

app.get("/user_panel/:email", checkNotAuthenticated, (req, res) => {
  var email = req.params.email;
  pool.query(
    `SELECT * FROM users
    WHERE email = $1`,
    [email],
    (err, results) => {
      if (err) {
        throw err;
      }
      res.render("user_panel", { user: req.user,user_config:results.rows[0] });
    }
  );  
});

app.get("/users/logout", (req, res) => {
  req.logout();
  res.render("index", { message: "You have logged out successfully" });
});



// User Registration
app.post("/users/register", async (req, res) => {
  let { name, email, password, password2, plan } = req.body;
  let errors = [];
  let status =true;

  if (!name || !email || !password || !password2 || !plan || plan == '0') {
    errors.push({ message: "Please enter all fields" });
  }

  if (password.length < 6) {
    errors.push({ message: "Password must be a least 6 characters long" });
  }

  if (password !== password2) {
    errors.push({ message: "Passwords do not match" });
  }

  if (errors.length > 0) {
    res.render("register", { errors, name, email, password, password2, plan });
  } else {
    hashedPassword = await bcrypt.hash(password, 10);
    // Validation passed
    pool.query(
      `SELECT * FROM users
        WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
        }

        if (results.rows.length > 0) {
          return res.render("register", {
            message: "Email already registered"
          });
        }
        else {
          pool.query(
            `INSERT INTO users (name, email, password, plan, status)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, password`,
            [name, email, hashedPassword, plan,status],
            (err, results) => {
              if (err) {
                throw err;
              }
              req.flash("success_msg", "You are now registered. Please log in");
              res.redirect("/users/login");
            }
          );
        }
      }
    );
  }
});

// Authentication

app.post(
  "/users/login",
  passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/users/login",
    failureFlash: true
  })
);

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/users/dashboard");
  }
  next();
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/users/login");
}


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});


// Password change routes


app.get("/forgotpassword", (req, res) => {
  res.render("forgotpassword.ejs");
});

app.get("/changepassword", checkNotAuthenticated, (req, res) => {
  res.render("changepassword", { user: req.user.name });
});

app.get("/resetpassword/:token", (req, res) => {
  res.render("resetpassword.ejs");
});

app.get("/user_panel/change/:email", checkNotAuthenticated, (req, res) => {
  var email = req.params.email;
  pool.query(
    `SELECT * FROM users
    WHERE email = $1`,
    [email],
    (err, results) => {
      if (err) {
        throw err;
      }
      var status;
      if(results.rows[0].status)
      {
        status=false;
      }
      else
      {
        status=true;
      }
      pool.query(
        `UPDATE users
        SET status = $1 
        WHERE email = $2`,
        [status, email],
        (err, results) => {
          if (err) {
            throw err;
          }
          res.send({val:'changed'});
        }
      );
    }
  );  
});

app.post("/changeUserPassword", checkNotAuthenticated, async(req, res) => {
  let { password, password_2, email } = req.body;
  hashedPassword = await bcrypt.hash(password, 10);
  pool.query(
    `SELECT * FROM users
    WHERE email = $1`,
    [email],
    (err, results) => {
      if (err) {
        console.log(err);
      }
      if(password!==password_2)
      {         
        req.flash("success_msg", "Passwords do not match");
        res.redirect("/changepassword");
      }
      else {
        pool.query(
          `UPDATE users
          SET password = $1 
          WHERE email = $2`,
          [hashedPassword,email],
          (err, results) => {
            if (err) {
              throw err;
            }
            res.send();
          }
        );
      };
    }
  );
});

app.post("/changepassword", checkNotAuthenticated, async(req, res) => {
  let { password, password_2 } = req.body;
  hashedPassword = await bcrypt.hash(password, 10);
  pool.query(
    `SELECT * FROM users
    WHERE email = $1`,
    [req.user.email],
    (err, results) => {
      if (err) {
        console.log(err);
      }
      if(password!==password_2)
      {         
        req.flash("success_msg", "Passwords do not match");
        res.redirect("/changepassword");
      }
      else {
        pool.query(
          `UPDATE users
          SET password = $1 
          WHERE email = $2`,
          [hashedPassword, req.user.email],
          (err, results) => {
            if (err) {
              throw err;
            }
            res.render("dashboard", { user: req.user.name });
          }
        );
      };
    }
  );
});

app.post("/forgotpassword", async (req, res) => {
  let { email } = req.body;
  const token = Math.floor(Math.random() * 100000000000);
  pool.query(
    `SELECT * FROM users
    WHERE email = $1`,
    [email],
    (err, results) => {
      if (err) {
        console.log(err);
      }
      if (results.rows.length == 0) {
        req.flash("success_msg", "Email does not exist!");
        res.redirect("/forgotpassword");
      }
      else {
        pool.query(
          `UPDATE users
          SET forgot_pass_token = ${token} 
          WHERE email = $1`,
          [email],
          (err, results) => {
            if (err) {
              throw err;
            }
            var mailOptions = {
              from: `${process.env.EMAIL}`,
              to: `${email}`,
              subject: 'Sending email from Nodejs',
              text: `http://localhost:3000/resetpassword/${token}`
            };           
            transporter.sendMail(mailOptions, function(error, info){
              if(error) {
                  console.log(error);
              } else {
                  console.log('Email sent: '+ info.response);
              }
            });

            req.flash("success_msg", "Check your mail");
            res.redirect("/forgotpassword");
          }
        );
      }
    }
  );
});


app.post("/resetpassword/:token", async (req, res) => {
  let { password, password_2 } = req.body;
  let token = req.params.token;
  hashedPassword = await bcrypt.hash(password, 10);
  pool.query(
    `SELECT * FROM users
    WHERE forgot_pass_token = $1`,
    [token],
    (err, results) => {
      if (err) {
        console.log(err);
      }
      if (results.rows.length == 0) {
        req.flash("success_msg", "Invalid token");
        res.redirect("/resetpassword/"+token);
      }
      else if(password!==password_2)
      {         
        req.flash("success_msg", "Passwords do not match");
        res.redirect("/resetpassword/"+token);
      }
      else {
        pool.query(
          `UPDATE users
          SET password = $1 
          WHERE forgot_pass_token = $2`,
          [hashedPassword, token],
          (err, results) => {
            if (err) {
              throw err;
            }
            req.flash("success_msg", "Your Password has successfuly changed!");
            res.redirect("/users/login");
          }
        );
      }
    }
  );
});

