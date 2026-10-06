const path = require("node:path");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;
const { body, validationResult } = require("express-validator");
const pool = require("./db/pool");
require("dotenv").config();

const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "cats",
    resave: false,
    saveUninitialized: false,
  })
);

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username." });
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return done(null, false, { message: "Incorrect password." });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = rows[0];
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use(passport.session());

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", async (req, res, next) => {
  try {
    const { rows } = await pool.query(`
      SELECT messages.id, messages.title, messages.text, messages.timestamp,
             users.first_name, users.last_name, users.username
      FROM messages
      JOIN users ON messages.user_id = users.id
      ORDER BY messages.timestamp DESC
    `);

    res.render("index", { 
      title: "Clubhouse - Home", 
      messages: rows 
    });
  } catch (err) {
    return next(err);
  }
});

app.get("/sign-up", (req, res) => {
  res.render("sign-up-form", { title: "Sign Up - Clubhouse" });
});

const validateSignUp = [
  body("first_name").trim().notEmpty().withMessage("First name is required."),
  body("last_name").trim().notEmpty().withMessage("Last name is required."),
  body("username")
    .trim()
    .isEmail().withMessage("Please enter a valid email address.")
    .custom(async (value) => {
      const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [value]);
      if (rows.length > 0) {
        throw new Error("Email is already in use.");
      }
    }),
  body("password")
    .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long."),
  body("confirmPassword").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Passwords do not match.");
    }
    return true;
  }),
];

app.post("/sign-up", validateSignUp, async (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.render("sign-up-form", {
      title: "Sign Up - Clubhouse",
      errors: errors.array(),
      formData: req.body,
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    await pool.query(
      "INSERT INTO users (first_name, last_name, username, password, membership_status, is_admin) VALUES ($1, $2, $3, $4, $5, $6)",
      [
        req.body.first_name,
        req.body.last_name,
        req.body.username,
        hashedPassword,
        false,
        false
      ]
    );

    res.redirect("/log-in");
  } catch (err) {
    return next(err);
  }
});

app.get("/log-in", (req, res) => {
  res.render("log-in-form", { title: "Log In - Clubhouse" });
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/log-in",
  })
);

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

const validateMessage = [
  body("title").trim().notEmpty().withMessage("Title is required."),
  body("text").trim().notEmpty().withMessage("Message text is required."),
];

app.get("/new-message", (req, res) => {
  if (!req.user) {
    return res.redirect("/log-in");
  }

  res.render("new-message", { title: "Create New Message - Clubhouse" });
});

app.post("/new-message", validateMessage, async (req, res, next) => {
  if (!req.user) {
    return res.redirect("/log-in");
  }

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.render("new-message", {
      title: "Create New Message - Clubhouse",
      errors: errors.array(),
      formData: req.body,
    });
  }

  try {
    await pool.query(
      "INSERT INTO messages (title, text, user_id) VALUES ($1, $2, $3)",
      [req.body.title, req.body.text, req.user.id]
    );

    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

app.get("/join-club", (req, res) => {
  if (!req.user) {
    return res.redirect("/log-in");
  }

  if (req.user.membership_status) {
    return res.redirect("/");
  }

  res.render("join-club", { title: "Join the Club - Clubhouse" });
});

app.post("/join-club", async (req, res, next) => {
  if (!req.user) {
    return res.redirect("/log-in");
  }

  const secretPasscode = process.env.CLUB_PASSCODE || "odin";

  if (req.body.passcode !== secretPasscode) {
    return res.render("join-club", {
      title: "Join the Club - Clubhouse",
      error: "Incorrect secret passcode. Try again!",
    });
  }

  try {
    await pool.query(
      "UPDATE users SET membership_status = true WHERE id = $1",
      [req.user.id]
    );

    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

function isAdmin(req, res, next) {
  if (req.user && req.user.is_admin) {
    return next();
  }
  res.status(403).send("Access denied. Admin privileges required.");
}

app.post("/message/:id/delete", isAdmin, async (req, res, next) => {
  try {
    await pool.query("DELETE FROM messages WHERE id = $1", [req.params.id]);
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});