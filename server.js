const express = require('express');
const passport = require('passport');
const cors = require('cors');
const dotenv = require('dotenv');
const userService = require('./user-service.js');
const jwt = require('jsonwebtoken');
const passportJWT = require('passport-jwt');

dotenv.config();
const app = express();
const HTTP_PORT = process.env.PORT || 8080;

// Middleware
app.use(express.json());
app.use(cors());

// Passport JWT Strategy
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;

passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
}, (jwtPayload, done) => {
    return done(null, jwtPayload);  // Pass user data to the route
}));

// Register Route (Sign up a new user)
app.post("/api/user/register", (req, res) => {
    userService.registerUser(req.body)
        .then((msg) => {
            res.json({ "message": msg });
        }).catch((msg) => {
        res.status(422).json({ "message": msg });
    });
});

// Login Route (Authenticate and return a JWT)
app.post("/api/user/login", (req, res) => {
    userService.checkUser(req.body)
        .then((user) => {
            // Create JWT payload
            const payload = { _id: user._id, username: user.username };
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.json({ "message": "Login successful", token });
        }).catch(msg => {
        res.status(422).json({ "message": msg });
    });
});

// Protected Route: Get Favourites
app.get("/api/user/favourites", passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.getFavourites(req.user._id)  // Extract user._id from JWT
        .then(data => {
            res.json(data);
        }).catch(msg => {
        res.status(422).json({ error: msg });
    });
});

// Protected Route: Add Favourite
app.put("/api/user/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.addFavourite(req.user._id, req.params.id)
        .then(data => {
            res.json(data);
        }).catch(msg => {
        res.status(422).json({ error: msg });
    });
});

// Protected Route: Remove Favourite
app.delete("/api/user/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.removeFavourite(req.user._id, req.params.id)
        .then(data => {
            res.json(data);
        }).catch(msg => {
        res.status(422).json({ error: msg });
    });
});

// Protected Route: Get History
app.get("/api/user/history", passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.getHistory(req.user._id)
        .then(data => {
            res.json(data);
        }).catch(msg => {
        res.status(422).json({ error: msg });
    });
});

// Protected Route: Add to History
app.put("/api/user/history/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.addHistory(req.user._id, req.params.id)
        .then(data => {
            res.json(data);
        }).catch(msg => {
        res.status(422).json({ error: msg });
    });
});

// Protected Route: Remove from History
app.delete("/api/user/history/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    userService.removeHistory(req.user._id, req.params.id)
        .then(data => {
            res.json(data);
        }).catch(msg => {
        res.status(422).json({ error: msg });
    });
});

// Start the Server
userService.connect()
    .then(() => {
        app.listen(HTTP_PORT, () => {
            console.log("API listening on: " + HTTP_PORT);
        });
    })
    .catch((err) => {
        console.log("Unable to start the server: " + err);
        process.exit();
    });
