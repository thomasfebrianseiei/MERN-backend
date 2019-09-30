const express = require("express");
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const validateRegisterInput = require("../validation/register");
const validateLoginInput = require("../validation/login");

const User = require("../models/user");

module.exports = {
  addUser: (req, res) => {
    const { errors, isValid } = validateRegisterInput(req.body);

    if (!isValid) {
      return res.status(400).json(errors);
    }
    User.findOne({
      email: req.body.email
    }).then(user => {
      if (user) {
        return res.status(400).json({
          email: "Email already exists"
        });
      } else {
        const avatar = gravatar.url(req.body.email, {
          s: "200",
          r: "pg",
          d: "mm"
        });
        const newUser = new User({
          name: req.body.name,
          email: req.body.email,
          password: req.body.password,
          avatar
        });

        bcrypt.genSalt(10, (err, salt) => {
          if (err) console.error("There was an error", err);
          else {
            bcrypt.hash(newUser.password, salt, (err, hash) => {
              if (err) console.error("There was an error", err);
              else {
                newUser.password = hash;
                newUser.save().then(user => {
                  res.json(user);
                });
              }
            });
          }
        });
      }
    });
  },
  login: (req, res) => {
    const { errors, isValid } = validateLoginInput(req.body);

    if (!isValid) {
      return res.status(400).json(errors);
    }

    const email = req.body.email;
    const password = req.body.password;

    User.findOne({ email }).then(user => {
      if (!user) {
        errors.email = "User not found";
        return res.status(404).json(errors);
      }
      bcrypt.compare(password, user.password).then(isMatch => {
        if (isMatch) {
          const payload = {
            id: user.id,
            name: user.name,
            avatar: user.avatar
          };
          jwt.sign(
            payload,
            "secret",
            {
              expiresIn: 3600
            },
            (err, token) => {
              if (err) console.error("There is some error in token", err);
              else {
                res.json({
                  success: true,
                  token: `Bearer ${token}`
                });
              }
            }
          );
        } else {
          errors.password = "Incorrect Password";
          return res.status(400).json(errors);
        }
      });
    });
  },
  getAuth: (req, res) => {
    passport.authenticate("jwt", { session: false }),
      (req, res) => {
        return res.json({
          id: req.user.id,
          name: req.user.name,
          email: req.user.email
        });
      };
  }
};


// I have defined the two post routes.

// Register,Login.

// Inside the post route of the register, we first check the validation for all of our inputs. If the errors exist, then there is no need for the further process. So sent back the error response to the client.

// After that, we check, if the email already exists, if so we need to send an error response to the client.

// Otherwise, we fetch the avatar based on email address, if an avatar is not there then by default will be sent back as a response.

// Then we create a hash value of the password and save the user in the database successfully and send back that user to the client.

// Now, for login the user, first, we check the validation same as a register.

// Then go for checking the email, and if the email is not found, then we send back the error to the client saying that user is not found.

// If email is proper, then we check password with bcrypt’s compare method. If the match is found, then we need to generate the jwt token.

// We use the user object as a payload and give a secret key to generate JWT token and send back that token to the user and logged in the user.

// Also, I have used get route, and that is /me.

// If the user is logged in and it has the jwt token then and then it can access this route otherwise he will redirect back to log in because this route is protected.