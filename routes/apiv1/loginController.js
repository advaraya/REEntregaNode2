"use strict";

const jwt = require("jsonwebtoken");
const Usuario = require("../../models/Usuario");
const bcrypt = require("bcrypt");

// POST /apiv1/authenticate

async function postJWT(req, res, next) {
  try {
    //Recoger los parametro de entrada
    const email = req.body.email;
    const password = req.body.password;

    //Buscar el usuario --> Crear un usuario y hacer require model
    const usuario = await Usuario.findOne({ email: email });

    //Si no existe el usuario o la password no coincide
    if (!usuario || !(await bcrypt.compare(password, usuario.password))) {
      const error = new Error("Invalid credentials");
      error.status = 401;
      next(error);
      return;
    }

    //Encuentro el usuario y la password es correcta --> Crear un JWT y luego responder entregandolo

    //crear JWT
    const token = jwt.sign({ _id: usuario._id }, process.env.JWT_SECRET, {
      expiresIn: "2d",
    });

    // responder
    res.json({ token: token });
  } catch (err) {
    next(err);
  }
}

module.exports = { postJWT };
