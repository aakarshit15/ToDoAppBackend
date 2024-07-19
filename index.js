import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import bcrypt from "bcrypt";
import GoogleStrategy from "passport-google-oauth2";
import cors from "cors";

env.config();

pg.types.setTypeParser(pg.types.builtins.DATE, value => value);

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
app.use(cors({
    origin: "http://localhost:5173/",
    optionsSuccessStatus: 200
}));
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
                                const user = result1.rows[0];
                                delete user.password;
                                return cb(null, user);
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

passport.use(
    "google",
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_OAUTH_CLIENT_ID,
            clientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_OAUTH_CALLBACK_URL,
            userProfileURL: process.env.GOOGLE_OAUTH_USER_PROFILE_URL
        },
        async (accessToken, refreshToken, profile, cb) => {
            try{
                const result1 = await db.query("SELECT * FROM users WHERE username = $1", [profile.email.split("@")[0]]);
                if(result1.rows.length === 0) {
                    try {
                        const result2 = await db.query("INSERT INTO users (username, password, name, email) VALUES ($1, $2, $3, $4) RETURNING *", [profile.email.split("@")[0], "google", profile.displayName, profile.email]);
                        const user = result2.rows[0];
                        delete user.password;
                        return cb(null, user);
                    } catch (err2) {
                        console.error(`Error inserting google profile details ${err1}`);
                        return cb(err2, false);
                    }
                } else {
                    const user = result1.rows[0];
                    delete user.password;
                    return cb(null, user);
                }
            } catch(err) {
                console.log(`Error executing google strategy: ${err}`);
                return cb(err, false);
            }
        }
    )
);

passport.serializeUser((user, cb) => {
    return cb(null, user);
});

passport.deserializeUser((user, cb) => {
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
                            await db.query("INSERT INTO users (username, password, name, email) VALUES ($1, $2, $3, $4)", [req.body.username, hash, req.body.name, req.body.email]);
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

app.get("/api/auth/google", passport.authenticate(
    "google",
    {
        scope: ["profile", "email"]
    }
));

app.get("/auth/google/user", passport.authenticate(
    "google",
    {
        successRedirect: "http://localhost:5173",
        failureRedirect: "/api/login"
    }
));

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

app.post("/api/addTaskList", async (req, res) => {
    if(req.user && req.isAuthenticated()) {
        try {
            const result1 = await db.query("SELECT * FROM task_lists WHERE list_date = $1 AND user_id = $2", [req.body.list_date, req.user.id]);
            if(result1.rows.length === 0) {
                try {
                    await db.query("INSERT INTO task_lists (list_date, user_id) VALUES ($1, $2)", [req.body.list_date, req.user.id]);
                    res.json({taskListMsg: `Task List with date ${req.body.list_date} added successfully`, taskListSuccess:true});
                } catch (err2) {
                    console.error(`Error executing task list inserting query: ${err2}`);
                    res.json({taskListMsg: err2, taslListSuccess: false});
                }
            } else {
                res.json({taskListMsg: `Task list with date ${req.body.date} already exits!!!`, taskListSuccess: false});
            }
        } catch (err1) {
            console.error(`Error executing search query: ${err1}`);
            res.json({taskListMsg: err1, taslListSuccess: false});

        }
    } else {
        res.redirect("/api/login");
    }
});

app.post("/api/addTask", async (req, res) => {
    if(req.user && req.isAuthenticated()) {
        try {
            await db.query("INSERT INTO tasks (title, task_list_id) VALUES ($1, $2)", [req.body.title, req.body.task_list_id]);
            res.json({taskMsg: "Task added successfully!!!", taskSuccess: true});
        } catch (err) {
            console.error(`Error executing task inserting query ${err}`);
            res.json({taskMsg:err ,taskSuccess: true});
        }
    } else {
        res.redirect("/api/login");
    }
});

app.patch("/api/toggleDone", async (req, res) => {
    if(req.user && req.isAuthenticated()) {
        await db.query("UPDATE tasks SET done = $1 WHERE id = $2", [!(req.body.done), req.body.id]);
        res.json({toggleDoneSuccess: true});
    } else {
        res.redirect("/api/login");
    }
});

app.patch("/api/editTask", async (req, res) => {
    if(req.user && req.isAuthenticated()) {
        await db.query("UPDATE tasks SET title = $1 WHERE id = $2", [req.body.title, req.body.id]);
        res.json({editTaskSuccess: true});
    } else {
        res.redirect("/api/login");
    }
});

app.delete("/api/deleteTask/:id", async (req, res) => {
    if(req.user && req.isAuthenticated) {
        await db.query("DELETE FROM tasks WHERE id = $1", [req.params.id]);
        res.json({deleteTaskSuccess: true});
    } else {
        res.redirect("/api/login");
    }
});

app.post("/api/getTasks", async (req, res) => {
    if(req.user && req.isAuthenticated()) {
        try {
            const listResult = await db.query("SELECT id, list_date FROM task_lists WHERE user_id = $1 ORDER BY list_date", [req.user.id]);
            if(listResult.rows.length === 0) {
                res.json({tasksList:[], getTasksMsg: "No tasks list present!!!", getTasksSuccess:true});
            } else {
                let taskLists = [...listResult.rows]
                try {
                    for(let i=0; i<taskLists.length; i++) {
                        const taskResult = await db.query("SELECT id, title, done FROM tasks WHERE task_list_id = $1 ORDER BY id", [taskLists[i].id]);
                        taskLists[i].tasks = taskResult.rows;
                    }
                    res.json({taskLists: taskLists, getTasksSuccess:true});
                } catch (err2) {
                    console.error(`Error searching tasks: ${err2}`);
                    res.json({getTasksMsg: err2, getTasksSuccess:false});
                }
            }
        } catch (err1) {
            console.error(`Error searching task lists: ${err1}`);    
            res.json({getTasksMsg: err1, getTasksSuccess:false});
        }
    } else {
        res.redirect("/api/login");
    }
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});