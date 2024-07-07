import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import bcrypt from "bcrypt";

// Username: aakarshit2003
// Password: 12345

env.config();

const app = express();
const port = parseInt(process.env.SERVER_PORT);
const saltRounds = parseInt(process.env.SALT_ROUNDS);
const db = new pg.Client({
    user: process.env.PG_USERNAME,
    password: process.env.PG_PASSWORD,
    database: process.env.PG_DATABASE,
    host: process.env.PG_HOST,
    port: parseInt(process.env.PG_PORT)
});
db.connect();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.json());
app.use(session({
    secret: process.env.SESSION_SECRET_WORD,
    resave: "false",
    saveUninitialized: "true",
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(
    "local",
    new Strategy(
        async (username, password, cb) => {
            try {
                const result1 = await db.query("SELECT * FROM users WHERE username = $1", [username]);
                if(result1.rows.length === 0) {
                    return cb(null, false);
                } else {
                    bcrypt.compare(password, result1.rows[0].password, (err2, result) => {
                        if(err2) {
                            console.error(`Error comparing password: ${err2}`);
                            return cb(err2, false);
                        } else {
                            if(result) {
                                return cb(null, result1.rows[0]);
                            } else {
                                return cb(null, false);
                            }
                        }
                    });
                }
            } catch (err1) {
                console.error(`Error executing query 1: ${err1}`);
                return cb(err1, false);
            }
        }
    )
);

passport.serializeUser((user, cb) => {
    // console.log("Serialize");
    // console.log(user);
    // console.log(typeof(user));
    return cb(null, user);
});

passport.deserializeUser((user, cb) => {
    // console.log("Deserialize");
    // console.log(user);
    return cb(null, user);
});

app.post("/api/register", async (req, res) => {
    if(req.body.password1 === req.body.password2) {
        try {
            const result1 = await db.query("SELECT * FROM users WHERE username = $1", [req.body.username]);
            if(result1.rows.length === 0) {
                try {
                    bcrypt.hash(req.body.password1, saltRounds, async (err, hash) => {
                        if(err) {
                            console.error(`Error hashing passwrod: ${err}`)
                            res.json({registerationSuccessful: false, registerationMessage: err});
                        } else {
                            await db.query("INSERT INTO users (username, password, name) VALUES ($1, $2, $3)", [req.body.username, hash, req.body.name]);
                            res.json({registerationSuccessful: true});
                        }
                    });
                } catch(err) {
                    console.error(`Error executing insert query: ${err}`);
                    res.json({registerationSuccessful: false, registerationMessage: err});
                }
            } else {
                res.json({registerationSuccessful: false, registerationMessage: "USER ALREADY EXITS!!!"});
            }
        } catch (err) {
            console.error(`Error executing search query: ${err}`);
            res.json({registerationSuccessful: false, registerationMessage: err});
        }
    } else {
        res.json({registerationSuccessful: false});
    }
});

app.post("/api/login", passport.authenticate(
    "local",
    {
        successRedirect: "/api/dashboard",
        failureRedirect: "/api/login",
    }
));

app.post("/api/logout", (req, res) => {
    req.logout((err) => {
        if(err) {
            console.error(`Error logging out ${err}`);
        } else {
            req.session.destroy(() => {
                res.redirect("/api/login");
            });
        }
    });
});

app.get("/api/dashboard", (req, res) => {
    if(req.user) {
        res.json({...req.user, isAuthenticated: req.isAuthenticated()});
    } else {
        res.redirect('/api/login');
    }
});

app.get("/api/login", (req, res) => {
    res.json({isAuthenticated: false});
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});