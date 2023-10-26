const db = require('../Config/connection')
var collection = require('../Config/collection')
const bcrypt = require('bcrypt');
const nodemailer = require("nodemailer");
const jwt = require('jsonwebtoken')
const jwtsecret = process.env.JWTSECRET
require("dotenv").config();
// email config
const tarnsporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
    }
})


exports.userregister = async (req, res) => {
    const userDetails = req.body;

    if (!userDetails.fname || !userDetails.email || !userDetails.password) {
        res.status(400).json({ error: "Please Enter All Input Data" });
    }

    try {
        const presuer = await db.get().collection(collection.userCollection).findOne({ email: userDetails.email });

        if (presuer) {
            res.status(409).json({ error: "This User Already Exists in our database" });
        } else {
            userDetails.password = await bcrypt.hash(userDetails.password, 10);
            const data = await db.get()
                .collection(collection.userCollection)
                .insertOne(userDetails);

            res.status(200).json({ storeData: data.insertedId });
        }
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "Server Error", error });
    }

};



// user send otp
exports.userOtpSend = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        res.status(400).json({ error: "Please Enter Your Email" })
    }


    try {
        const presuer = await db.get().collection(collection.userCollection).findOne({ email: email });

        if (presuer) {
            const OTP = Math.floor(100000 + Math.random() * 900000);

            const existEmail = await db.get().collection(collection.otpCollection).findOne({ email: email });


            if (existEmail) {


                const updateData = await db.get().collection(collection.otpCollection).findOneAndUpdate(
                    { _id: existEmail._id },
                    { $set: { otp: OTP } },
                    { returnOriginal: false }
                );



                const mailOptions = {
                    from: process.env.EMAIL,
                    to: email,
                    subject: "Sending Eamil For Otp Validation",
                    text: `OTP:- ${OTP}`
                }


                tarnsporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log("error", error);
                        res.status(400).json({ error: "email not send" })
                    } else {
                        console.log("Email sent", info.response);
                        res.status(200).json({ message: "Email sent Successfully" })
                    }
                })

            } else {
                userDetails = {
                    email,
                    otp: OTP
                }
                const data = await db.get()
                    .collection(collection.otpCollection)
                    .insertOne(userDetails);
                const mailOptions = {
                    from: process.env.EMAIL,
                    to: email,
                    subject: "Sending Eamil For Otp Validation",
                    text: `OTP:- ${OTP}`
                }

                tarnsporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log("error", error);
                        res.status(400).json({ error: "email not send" })
                    } else {
                        console.log("Email sent", info.response);
                        res.status(200).json({ message: "Email sent Successfully" })
                    }
                })
            }
        } else {
            res.status(400).json({ error: "This User Not Exist In our Db" })
        }
    } catch (error) {
        res.status(400).json({ error: "Invalid Details", error })
    }
};


exports.userLogin = async (req, res) => {
    const { email, otp } = req.body;
    if (!otp || !email) {
        res.status(400).json({ error: "Please Enter Your OTP and email" });
        return; // Return early to prevent further execution.
    }

    try {
        const otpverification = await db.get().collection(collection.otpCollection).findOne({ email: email });
        const otpveri = parseInt(otp);
        if (otpverification.otp === otpveri) {
            const preuser = await db.get().collection(collection.userCollection).findOne({ email: email });

            const token = jwt.sign({
                email: preuser.email,
                id: preuser._id,
            }, jwtsecret, { expiresIn: '1d' });

            res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none' }, {
                email: preuser.email,
                id: preuser._id,
            });

            res.status(200).json({ message: "User Login Successfully Done", token });
        } else {
            res.status(400).json({ error: "Invalid Otp" });
        }
    } catch (error) {
        res.status(400).json({ error: "Invalid Details", error });
    }
};
exports.userLogout = (req, res) => {
    res.clearCookie('token');
    res.status(200).json({ message: 'Logout successful' });
}