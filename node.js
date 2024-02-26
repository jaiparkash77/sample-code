// Steps to create rest API using express
//-----------Step 1 - Initilize project and install dependencies - 
// Dependencies - express,jsonwebtoken,mongoose,zod,bcryptjs - cors (frontend - optional) ; devDependencies - dotenv,nodemon
// Change in package.json for entry point ("main": "server.js")

//-----------Step 2 - Create express app - server.js
require('dotenv').config();
const express = require("express");
const cors = require("cors");
const authRoute = require("./router/auth-router");
const adminRoute = require("./router/admin-router");
const connectDB = require("./utils/db");
const errorMiddleware = require('./middlewares/error-middleware');

const app = express();

// Handling cors policy issue
const corsOptions = {
    origin: "http://localhost:5173",
    methods: "GET, POST, PUT, DELETE, PATCH, HEAD",
    credentials: true
}
app.use(cors(corsOptions));

app.use(express.json());

app.use("/api/auth", authRoute);

// Admin Route
app.use("/api/admin", adminRoute)

app.use(errorMiddleware);

const PORT = process.env.PORT || 5000;

connectDB().then(()=>{
    app.listen(PORT, ()=>{
        console.log(`Server is running on port ${PORT}`);
    })
})

// -----------Step 3 - utils/db.js
const mongoose = require("mongoose");

// const URI = "mongodb://127.0.0.1:27017/neohub"
const URI = process.env.MONGODBURI;

const connectDB = async ()=>{
    try {
        await mongoose.connect(URI);
        console.log("Connection successfully to DB");
    } catch (error) {
        console.error("Database connection failed");
        process.exit(0)
    }
}

module.exports = connectDB;

// ----------- Step 4 - Auth Route - router/auth-router.js
const express = require("express");
const router = express.Router();
const authcontrollers = require("../controllers/auth-controller");
const {signupSchema, loginSchema} = require("../validators/auth-validator");
const validate = require("../middlewares/validate-middleware");
const authMiddleware = require("../middlewares/auth-middleware");

router.route("/").get(authcontrollers.home);

router.route("/register").post(validate(signupSchema), authcontrollers.register);
router.route("/login").post(validate(loginSchema) ,authcontrollers.login);
router.route("/user").get(authMiddleware, authcontrollers.user);

module.exports = router;

// ------------- Step 5 - Model - models/user-model.js
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        require: true,
    },
    email: {
        type: String,
        require: true,
    },
    password: {
        type: String,
        require: true
    },
    phone: {
        type: Number,
        require: true
    },
    isAdmin: {
        type: Boolean,
        default: false
    }
});

// Secure the password with bcrypt
userSchema.pre("save", async function(next){
    // console.log("Pre method", this)
    const user = this;

    if(!user.isModified("password")){
        next();
    }

    try {
        const saltRound = await bcrypt.genSalt(10);
        const hash_password = await bcrypt.hash(user.password, saltRound);
        user.password = hash_password;
    } catch (error) {
        next(error)
    }
})

// JSON web token
// Token, such as JWTs (Json Web Tokens), are typically not stored in the database along with other user details. Instead, they are issued by the server during the authentication proccess and then stored on the client-side (e.g. in cookies or local storage) for later use.
userSchema.methods.generateToken = async function(){
    try {
        return jwt.sign({
            userId: this._id.toString(),
            email: this.email,
            isAdmin: this.isAdmin,
        }, 
        process.env.JWT_SECRET_KEY,
        {
            expiresIn: "30d"
        })
    } catch (error) {
        console.error(error);
    }
}

// Compare Password
userSchema.methods.comparePassword = async function(password){
    try {
        return bcrypt.compare(password, this.password);
    } catch (error) {
        console.error(error);
    }
}

const User = new mongoose.model("User", userSchema);

module.exports = User;

// ------------- Step 6 - Controllers - controllers/auth-controllers.js
const User = require("../models/user-model");
const bcrypt = require("bcryptjs");

const register = async (req, res, next) =>{
    try {
        const { username, email, password, phone} = req.body;
        let existingUser = await User.findOne({email});
        if(existingUser){
            return res.status(409).json({message:"Email Already in use."})
        }
        // Hash the password
        // const saltRound = 10;
        // const hash_password = await bcrypt.hash(password, saltRound);
        const user = await User.create({username, email, password, phone});
        res.status(201).json({message:'Registration successful', token: await user.generateToken(), userId: user._id.toString() });
    } catch (error) {
        // res.status(400).json({msg: "Registration failed"});
        next(error)
    }
}

const login = async(req, res)=>{
    try {
        const {email, password} = req.body;

        const userExist = await User.findOne({email});
        // console.log(userExist);

        if(!userExist){
            return res.status(400).json({message: "Invalid Credentials"});
        }

        // const user = await bcrypt.compare(password, userExist.password);
        const user = await userExist.comparePassword(password);

        if(user){
            res.status(200).json({
                message:'Login successful', 
                token: await userExist.generateToken(), 
                userId: userExist._id.toString() 
            });
        }else{
            res.status(401).json({message: "Invalid Email or Password"});
        }

    } catch (error) {
        res.status(500).json({msg: "Internal Server Error"});
    }
}

module.exports = { register, login}

// --------------- Step 7 - Validator - validators/auth-validators.js
const { z } = require("zod");

// Creating an object schema -
const loginSchema = z.object({
    email: z.string({required_error:"Email is required"})
    .trim()
    .email({ message : 'Please enter a valid Email'})
    .min(3,{message: "Email must be at least 3 charactors"})
    .max(255, {message: "Email must not be more than 255 charactors"}),
    password: z.string({required_error:"Password is required"})
    .min(7,{message: "Password must be at least 6 charactors"})
    .max(1024, {message: "Password must not be more than 1024 charactors"}),
});

//loginSchema.extend is extending email and password from login schema
const signupSchema = loginSchema.extend({
    username: z.string({required_error: "Username is required"})
    .trim()
    .min(3,{message: "Username must be at least 3 charactors"})
    .max(255, {message: "Username must not be more than 255 charactors"}),   
    phone: z.string({ message : 'Phone is required'})
    .trim()
    .min(10,{message: "Phone must be at least 10 charactors"})
    .max(20, {message: "Phone must not be more than 20 charactors"}),
});


module.exports = {signupSchema, loginSchema};


// -----------Step 8 - Auth Middleware - middlewares/auth-middlewares
const jwt = require("jsonwebtoken");
const User = require("../models/user-model");

const authMiddleware = async(req, res, next) =>{
    const token = req.header("Authorization");

    if(!token){
        // If you attempt to use an expired token, you'll recieve a "401 Unauthorized HTTP" response.
        return res.status(401).json({message: "Unauthorized HTTP, Token not provided"});
    }

    
    // Assuming token is in the format "Bearer <jwt token>, Removing the 'Bearer' prefix"
    const jwtToken = token.replace("Bearer", "").trim();
    // console.log("token from auth middleware", jwtToken);

    try {
        const isVerified = jwt.verify(jwtToken, process.env.JWT_SECRET_KEY);
        const userData = await User.findOne({email: isVerified.email}).select({password: 0});
        
        req.user = userData;
        req.token = token;
        req.userId = userData._id;

        next();
    } catch (error) {
        return res.status(401).json({message: "Unauthorized, Invalid token"});
    }
}

module.exports = authMiddleware;

// -------------Step 9 - Error Middleware - Optional - middlewares/error-middleware.js
const errorMiddleware = (err, req, res, next) =>{
    const status = err.status || 500;
    const message = err.message || "Backend Error";
    const extraDetails = err.extraDetails || "Error from backend";

    return res.status(status).json({message, extraDetails});
}

module.exports = errorMiddleware;

// ----------- Step 10 - Validate middleware - middlewares/validate-middleware.js
const validate = (schema) => async (req, res, next) => {
    try {
        const parseBody = await schema.parseAsync(req.body);
        req.body = parseBody;
        next();
    } catch (err) {
        const status = 422;
        const message = "Please fill the input properly";
        const extraDetails = err.errors[0].message;
        const error = {
            status,
            message,
            extraDetails
        }
        // res.status(400).json({message});
        next(error);
    }
}

module.exports = validate;