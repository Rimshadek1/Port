const { MongoClient } = require("mongodb");
require("dotenv").config();
const state = {
    db: null,
};
const mongoUrl = process.env.mongoUrl
// mongodb connection string
const url = mongoUrl;
// database name
const dbName = "Stake";

// create a new mongodb client object
const client = new MongoClient(url);

// function to establish mongodb connection
const connect = async (cb) => {
    try {
        // connecting to mongodb
        await client.connect();
        // setting up database name to the connected client
        const db = client.db(dbName);
        // setting up database name to the state
        state.db = db;
        // callback after connected
        return cb();
    } catch (err) {
        // callback when an error occurs
        return cb(err);
    }
};

// function to get the database instance
const get = () => state.db;

// exporting functions
module.exports = {
    connect,
    get,
};