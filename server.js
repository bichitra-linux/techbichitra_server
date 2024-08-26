import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import 'dotenv/config';
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import { getAuth } from "firebase-admin/auth";
import serviceAccountKey from "./thedailytech-b0eaa-firebase-adminsdk-bdyrp-1bef3cae92.json" assert {type: "json"};


//schema imports
import User from "./Schema/User.js";



const server = express();
server.use(express.json());
let PORT = "3000";
server.use(cors());

//firebase config
admin.initializeApp({
    credentials: admin.credential.cert(serviceAccountKey),
})


let emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;    // regex for e-mail
let passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;   // regex for password


// Connect to MongoDB
mongoose.connect(process.env.DB_LOCATION, {
    autoIndex: true
})

const formatDatatoSend = (user) => {

    const access_token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY)

    return {
        access_token: access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname,

    }
}

const generateUsername = async (email) => {
    let username = email.split(
        "@"
    )[0];
    let isUsernameNotUnique = await User.exists({ "personal_info.username": username }).then((result) => {
        return result;
    });

    isUsernameNotUnique ? username += nanoid().substring(0, 4) : "";

    return username;

}

// Check if the connection is successful 
server.post("/signup", (req, res) => {

    const { email, password, fullname } = req.body;

    if (fullname.length < 3) {
        return res.status(403).json({ error: "Full Name must be at least 3 characters long" })
    }
    if (!email.length) {
        return res.status(403).json({ error: "Email is required" })
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ error: "Invalid email" })
    }
    if (password.length < 8) {
        return res.status(403).json({ error: "Password must be at least 8 characters long" })
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ error: "Password must contain at least one uppercase letter, one lowercase letter, one number and one special character" })
    }

    bcrypt.hash(
        password,
        10,
        async (err, hash) => {

            let username = await generateUsername(email);

            let user = new User({
                personal_info: {
                    fullname: fullname,
                    email: email,
                    password: hash,
                    username: username
                }
            })

            user.save().then((u) => {
                return res.status(200).json(formatDatatoSend(u));
            }).catch((err) => {
                if (err.code === 11000) {
                    return res.status(500).json({ error: "Email already exists" });
                }
                return res.status(500).json({ error: "Internal server error" });
            });

        }
    )

    //return res.status(200).json({ "status": "ok" })



})

server.post("/signin", (req, res) => {
    const { email, password } = req.body;

    User.findOne({ "personal_info.email": email }).then((user) => {
        if (!user) {
            return res.status(403).json({ error: "User not found for this email" })
        }

        if(!user.google_auth){
            bcrypt.compare(password, user.personal_info.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ error: "Internal server error" })
                }
                if (!result) {
                    return res.status(403).json({ error: "Invalid password" })
                } else {
                    return res.status(200).json(formatDatatoSend(user))
                }
            })
        } else {
            return res.status(403).json({ error: "Please login with Google" })
        }
        


    })

    /*if (!email.length) {
        return res.status(403).json({ error: "Email is required" })
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ error: "Invalid email" })
    }

    if (password.length < 8) {
        return res.status(403).json({ error: "Password must be at least 8 characters long" })
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ error: "Password must contain at least one uppercase letter, one lowercase letter, one number and one special character" })
    }*/

    //return res.status(200).json({ "status": "ok" })
})

server.post("/google-auth", async (req, res) => {
    let { access_token } = req.body;

    getAuth()
        .verifyIdToken(access_token)
        .then(async (decodedToken) => {
            let { email, name, picture } = decodedToken;
            picture = picture.replace("s96-c", "s384-c");
            let user = await User.findOne({ "personal_info.email": email }).select("personal_info.fullname personal_info.username personal_info.profile_img google_auth").then((u) => {
                return u || null
            })
                .catch(err => {
                    return res.status(500).json({ "error": err.message })
                })

            if (user) {
                if (!user.google_auth) {
                    return res.status(403).json({ error: "User already registered without google account, please use email and password" })
                } else {
                    let username = await generateUsername(email);
                    user = new User({
                        personal_info: {
                            fullname: name,
                            email: email,
                            username: username,
                            profile_img: picture
                        },
                        google_auth: true
                    })
                    await user.save().then((u) => {
                        user = u;
                    })
                        .catch(err => {
                            return res.status(500).json({ "error": err.message })
                        })
                }
                return res.status(200).json(formatDatatoSend(user))
            }
        })
        .catch(err => {
            return res.status(500).json({ "error": "Failed to authenticate with Google, Try Again Later" })
        })
})

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
})