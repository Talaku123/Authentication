import express from "express"
import pg from "pg"
import { body, validationResult } from "express-validator"
import bcrypt from "bcrypt"
import env from "dotenv"
import session from "express-session"
import passport from "passport"
import { Strategy } from "passport-local"



env.config(); 

if (!process.env.DB_USER || !process.env.DB_HOST || !process.env.DB_NAME || !process.env.DB_PASSWORD || !process.env.DB_PORT) {
  console.error("Missing required environment variables. Please check your .env file.");
  process.exit(1);
}

const app = express()
const PORT = 3043


app.set("view engine", "ejs"); 


app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));


app.use(
  session({
    secret: "secrets",
    resave: false,
    saveUninitialized: true,
    cookie: {secure: false}
  })
)

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id); // Assuming 'id' is the primary key in your users table
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      done(null, result.rows[0]);
    } else {
      done(null, false);
    }
  } catch (err) {
    done(err, null);
  }
});


const db = new pg.Client(
{

    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: parseInt(process.env.DB_PORT, 10)
});


db.connect()
  .then(() => console.log("Postgres connected"))
  .catch((err) => console.error("Connection error", err.stack));
 


app.get("/", (_, res) => {
    res.render("home.ejs")
})


app.get("/login", (_, res) => {
    res.render("login.ejs")
})

app.get("/register", (_, res) => {
    res.render("register.ejs")
})

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
      res.render("secrets.ejs")
  } else {
      res.redirect("/login");
  }
})

app.post("/register",
[
  body("username").isEmail().withMessage("Invalid email"),
  body("password").isLength({min:8}).withMessage("Password must be at least 8 characters")
],

  async (req, res) => {
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({errors: errors.array()})
    }

    const email = req.body.username
    const password = req.body.password
    const hashedPassword = await bcrypt.hash(password, 10); 

    try 
    {
      const checkResult = await db.query("SELECT * FROM users WHERE email=$1", [email]);

      if (checkResult.rows.length > 0) {
        res.send("Email Is Existed...");
      } else {
        await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, hashedPassword]);
        res.render("secrets.ejs"); 
      }

    } catch (err) {
      console.log(err)
      res.status(500).send("An error found")
    }
  }
)



passport.use(new Strategy(async function verify(username, password, cb) {
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedPassword = user.password;

      const isMatch = await bcrypt.compare(password, storedPassword);
      if (isMatch) {
        return cb(null, user);
      } else {
        return cb(null, false, { message: "Incorrect password" });
      }
    } else {
      return cb(null, false, { message: "User not found" });
    }
  } catch (err) {
    console.log(err);
    return cb(err);
  }
}));

app.post("/login", passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));



app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`)
})