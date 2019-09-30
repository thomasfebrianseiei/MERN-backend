const express = require("express");
const router = express.Router();
const {addUser,login,getAuth} = require ('../controller/user')

router.post("/register",addUser);
router.post("/login",login);
router.get("/me",getAuth);

module.exports = router;
