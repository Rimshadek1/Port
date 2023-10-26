require("dotenv").config();
const express = require("express");
const app = express();
const cors = require("cors");
const db = require('./Config/connection')
const router = require("./Routes/router");
const PORT = process.env.port;
const bodyParser = require('body-parser');


// middleware
app.use(express.json());
app.use(bodyParser.json());
app.use(cors({
    origin: ['http://localhost:3000'],
    methods: ['GET', 'POST', 'DELETE'],
    credentials: true
}));
app.use(router);


// connection
db.connect((err) => {
    if (err)
        console.log('errrorrrr' + err);
    else
        console.log("Database connected");
})

app.listen(PORT, () => {
    console.log(`Server start at Port No :${PORT}`)
})
