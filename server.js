import express from "express";
import dotenv from "dotenv"
import bodyParser from "body-parser";
import cors from "cors"
import mongoose from "mongoose";
import User from "./models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer"

dotenv.config();
const app = express();
app.use(express.json())
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}))
app.use(cors());
// app.use(express.static("public"));

app.post("/register", async (req,res)=>{
    const {username,email,password} = req.body;
    
    const encryptedPassword = await bcrypt.hash(password,10);

    try{
        const existUser = await User.findOne({email})
        if(existUser){
            return res
            .status(409)
            .send({ message: "User with given email already Exist!" });
        }
     const userInfo = await User.create({
        username,
        email,
        password:encryptedPassword
     });
     res.status(200).send({message:"Successfully user created!"})
    }catch(error){
        res.status(400).json(error)
    }
})

app.post("/login", async (req,res)=>{
    const {email,password} = req.body;
    const user  = await User.findOne({email});
    if(!user){
        return res.json({error:"User not exist"})
    }
    if(await bcrypt.compare(password,user.password)){
        var token = jwt.sign({username:user.email},process.env.JWT_SECRET, {expiresIn: "15m"});
        if(res.status(200)){
            return res.send({status:"ok", data:token})
        }else{
            return res.send({error:"error"})
        }
    }
    res.status(400).send({error:"invalid password"})
})

app.post("/userinfo", async (req,res)=>{
    const {token} = req.body;
    try{
        const userToken = jwt.verify(token,process.env.JWT_SECRET,(err,res)=>{
            if(err){
                return "token is expired!"
            }
            return res;
        });
        if(userToken === "token is expired!"){
            return res.status(502).send("token expired!")
        }
        const username = userToken.email;
        User.findOne({username:username}).then((data)=>{
            res.status(200).json(data)
        }).catch((err)=>{
         res.status(502).json(err)
        })
    }catch(err){

    }
})

app.post("/forget-password",async(req,res)=>{
    const {email} = req.body;
    try{
        const existingUser = await User.findOne({email});
        if(!existingUser){
            return res
            .status(409)
            .send({ message: "User with given email does not exist!" }); 
        }
        const secret = process.env.JWT_SECRET + existingUser.password;
        const token = jwt.sign({email:existingUser.email, id:existingUser._id},secret,{expiresIn:"5m"});
        const link = `http://localhost:5000/reset-password/${existingUser._id}/${token}`;
       

        let transporter = nodemailer.createTransport({
            
            service: 'gmail',
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: 'cbc@gmail.com',
                pass: '123456789'
            },
          });
        let mailOptions ={
            from: 'cbc@gmail.com', // sender address
            to: 'fatimaara784@email.com',
            subject:"Forget Password Reset",
            text:link
        };

        transporter.sendMail(mailOptions,function(error,info) {
           if(error){
            console.log(error);
           }else{
            console.log(`Email sent on your mailbox : ${info}`)
           }
        });

        console.log(link);
        res
			.status(200)
			.send({ message: "Password reset link sent to your email account" });
	
    }catch(err){
        res.status(500).send({ message: "Internal Server Error" });
    }
})

app.get("/reset-password/:id/:token", async(req,res)=>{
    const {id,token} = req.params;
    const existingUser = await User.findOne({_id:id});
        if(!existingUser){
         return res.json({msg:"User not Exist!"})   
        }
        const secret = process.env.JWT_SECRET + existingUser.password;
        try{
            const verify = jwt.verify(token,secret)
            res.send("Verified");
        }catch(err){
          res.send("Not Verified!")
        }
})
app.post("/reset-password/:id/:token", async(req,res)=>{
    const {id,token} = req.params;
    const {password} = req.body;
    const existingUser = await User.findOne({_id:id});
        if(!existingUser){
         return res.json({msg:"User not Exist!"})   
        }
        const secret = process.env.JWT_SECRET + existingUser.password;
        try{
            const verify = jwt.verify(token,secret)
            const encryptedPassword = await bcrypt.hash(password,10);
            await User.updateOne({
                _id:id
            },
               {
                $set:{
                    password:encryptedPassword
                }
               }
            );
            res.json({msg:"Password updated!"})
            res.send("Verified");
        }catch(err){
          res.json({msg:"Something went wrong!"})
        }
})

// mongoose setup
const PORT = process.env.PORT ;
mongoose.connect(process.env.MONGO_URL,{
    useNewUrlParser:true,
    useUnifiedTopology:true
}).then(()=>{
    app.listen(PORT,()=>{
        console.log("Server running")
    })})
    .catch((err)=>
    console.log(err)
)