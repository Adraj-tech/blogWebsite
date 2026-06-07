import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import { v4 as uuidv4 } from "uuid";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const port = process.env.PORT || 3000;

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
// =================  VERIFICATION =================
const token = uuidv4();

await db.query(
  `INSERT INTO users (name,email,password,verification_token,is_verified)
   VALUES ($1,$2,$3,$4,false)`,
  [name, email, hashedPassword, token]
);

const link = `http://localhost:${port}/verify/${token}`;

await transporter.sendMail({
  to: email,
  subject: "Verify Email",
  html: `<a href="${link}">Verify Account</a>`,
});

// ================= DATABASE =================

const db = new pg.Client({
  connectionString:process.env.DATABASE_URL,
    
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect()
  .then(() => {
    console.log("Connected to Neon PostgreSQL");
  })
  .catch((err) => {
    console.log("Database Connection Error:", err);
  });

// ================= MIDDLEWARE =================

app.use(express.static("public"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

// ================= HOME =================

app.get("/", (req, res) => {

  res.render("index", {
    user: req.session.user,
  });

});

// ================= SIGNUP =================

app.get("/signup", (req, res) => {

  res.render("partials/signup");

});

app.post("/signup", async (req, res) => {

  const { name, email, password } = req.body;

  try {

    const passwordRegex =
      /^(?=.*[A-Z])(?=.*\d)(?=.*@).{6,}$/;

    if (!passwordRegex.test(password)) {

      return res.send(
        "Password must contain:<br><br>" +
        "• At least 6 characters<br>" +
        "• One uppercase letter<br>" +
        "• One number<br>" +
        "• One @ symbol"
      );

    }

    const existingUser = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {

      return res.send("Email already registered!");

    }

    const hashedPassword =
      await bcrypt.hash(password, 10);

    await db.query(
      `
      INSERT INTO users
      (name, email, password)

      VALUES ($1, $2, $3)
      `,
      [name, email, hashedPassword]
    );

    res.redirect("/signin");

  } catch (err) {

    console.log(err);

    res.send("Registration Error");

  }

});

// ================= SIGNIN =================

app.get("/signin", (req, res) => {

  res.render("partials/signin");

});

app.post("/signin", async (req, res) => {

  const { email, password } = req.body;

  try {

    const result = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {

      return res.send("User not found!");

    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {

      return res.send("Incorrect Password");

    }
    if (!user.is_verified) {
  return res.send("Please verify your email first");
}

    req.session.user = user;

    res.redirect("/");

  } catch (err) {

    console.log(err);

    res.send("Server Error");

  }

});
// ================= VERIFY =================
app.get("/verify/:token", async (req, res) => {
  const { token } = req.params;

  await db.query(
    `UPDATE users
     SET is_verified=true, verification_token=NULL
     WHERE verification_token=$1`,
    [token]
  );

  res.send("Email verified successfully");
});

// ================= BLOG PAGE =================

app.get("/blog", (req, res) => {

  if (!req.session.user) {

    return res.redirect("/signin");

  }

  res.render("blog", {
    user: req.session.user,
  });

});

app.post("/blog", async (req, res) => {

  if (!req.session.user) {

    return res.redirect("/signin");

  }

  const { title, content } = req.body;

  const user = req.session.user;

  try {

    await db.query(
      `
      INSERT INTO blogs
      (title, content, author_email, author_name)

      VALUES ($1, $2, $3, $4)
      `,
      [
        title,
        content,
        user.email,
        user.name,
      ]
    );

    res.redirect("/blogs");

  } catch (err) {

    console.log(err);

    res.send("Error Saving Blog");

  }

});

// ================= ALL BLOGS =================

app.get("/blogs", async (req, res) => {

  try {

    const result = await db.query(
      `
      SELECT *
      FROM blogs

      ORDER BY created_at DESC
      `
    );

    res.render("partials/blogs", {
      blogs: result.rows,
      user: req.session.user,
    });

  } catch (err) {

    console.log(err);

    res.send("Error Loading Blogs");

  }

});

// ================= SINGLE BLOG =================

app.get("/blogs/:title", async (req, res) => {

  const title = req.params.title;

  try {

    const result = await db.query(
      `
      SELECT *
      FROM blogs

      WHERE title = $1
      `,
      [title]
    );

    res.render("partials/blogs", {
      blogs: result.rows,
      user: req.session.user,
    });

  } catch (err) {

    console.log(err);

    res.send("Error Loading Blog");

  }

});

// ================= LOGOUT =================

app.get("/logout", (req, res) => {

  req.session.destroy((err) => {

    if (err) {

      console.log(err);

      return res.send("Error Logging Out");

    }

    res.redirect("/");

  });

});

// ================= SERVER =================

app.listen(port, () => {

  console.log(`Server running on port ${port}`);

});



