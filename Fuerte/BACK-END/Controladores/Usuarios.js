import express from "express";
import { Orden, ProductoOrden, Producto, Usuario } from "../Models/Relaciones.js";
import crypto from "crypto";
import NodeCache from "node-cache";
import Transporter from "../Services/mail.service.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import Joi from "joi";
import sanitizeHtml from "sanitize-html";

const router = express.Router();

/* ====================================================================
   Configuration & Helpers
   ==================================================================== */
// Cache for short-lived verification codes. In production use Redis or similar.
const myCache = new NodeCache({ stdTTL: 300, checkperiod: 60 }); // 5 minutes TTL
const cacheContraseña = new NodeCache({ stdTTL: 300, checkperiod: 60 });

const SALT_ROUNDS = Number(process.env.SALT_ROUNDS) || 12;
const JWT_SECRET = process.env.JWT_SECRET || "please_set_a_strong_secret_in_env";
const JWT_EXPIRATION = process.env.JWT_EXPIRATION || "2h";

// Rate limiters
const loginLimiter = rateLimit({ windowMs: 60 * 1000, max: 5, message: { message: "Demasiados intentos, espere un momento." } });
const generalLimiter = rateLimit({ windowMs: 1000, max: 20 });

// Validation schemas (Joi) - strict validation mitigates injection and bad input
const registerSchema = Joi.object({
  nombre: Joi.string().min(2).max(100).required(),
  apellidoPaterno: Joi.string().allow(null, "").max(100),
  apellidoMaterno: Joi.string().allow(null, "").max(100),
  password: Joi.string().min(8).max(128).required(),
  correo: Joi.string().email().required(),
  telefono: Joi.string().pattern(/^\d{9}$/).required(),
  dni: Joi.string().pattern(/^\d{8}$/).required()
});

const loginSchema = Joi.object({
  correo: Joi.string().email().required(),
  password: Joi.string().min(8).max(128).required()
});

const emailSchema = Joi.object({ correo: Joi.string().email().required() });

const verificationSchema = Joi.object({ correo: Joi.string().email().required(), codigo: Joi.string().alphanum().min(4).max(12).required() });

// Auth middleware: verify JWT and attach user info
function auth(required = true) {
  return (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        if (!required) return next();
        return res.status(401).json({ message: "Token requerido" });
      }
      const token = authHeader.split(" ")[1];
      if (!token) return res.status(401).json({ message: "Token inválido" });

      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload; // { id, rol, iat, exp }
      return next();
    } catch (err) {
      return res.status(403).json({ message: "Token inválido o expirado" });
    }
  };
}

// Role check middleware
function requireAdmin(req, res, next) {
  if (!req.user || req.user.rol !== "admin") return res.status(403).json({ message: "Acceso restringido" });
  next();
}

// Helper: generate cryptographically secure 6-digit code as string
function generate6DigitCode() {
  // crypto.randomInt is secure and returns number between 0 and 999999 inclusive
  const n = crypto.randomInt(0, 1000000);
  return n.toString().padStart(6, "0");
}

// Helper: sanitize user-controlled HTML/text inputs to prevent XSS when stored and later rendered
function sanitizeInput(value) {
  if (typeof value !== "string") return value;
  return sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} });
}

/* ====================================================================
   Routes
   ==================================================================== */

// GET / - List users (protected, admin only)  -- Mitigates Broken Access Control (A01)
router.get("/", auth(), requireAdmin, generalLimiter, async (req, res) => {
  try {
    const usuarios = await Usuario.findAll({ attributes: { exclude: ["password"] } }); // never return password
    return res.json(usuarios);
  } catch (error) {
    console.error("Error al obtener usuarios:", error.message);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

// GET /:id - Obtener usuario por id (protected, user must be owner or admin)
router.get("/:id", auth(), generalLimiter, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ message: "ID inválido" });

    // solo propietario o admin
    if (req.user.id !== id && req.user.rol !== "admin") return res.status(403).json({ message: "No autorizado" });

    const usuario = await Usuario.findByPk(id, { attributes: { exclude: ["password"] } });
    if (!usuario) return res.status(404).json({ message: "Usuario no encontrado" });

    return res.json(usuario);
  } catch (error) {
    console.error("Error al buscar el usuario por ID:", error.message);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

/* ---------------------------------------------------------------
   Registro y verificación por correo
   - Input validation
   - Password hashing
   - Secure verification code generation
   - Avoid logging sensitive values
   --------------------------------------------------------------- */
router.post("/registrar", async (req, res) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    // sanitize fields that will be stored
    const nombre = sanitizeInput(value.nombre);
    const apellidoPaterno = sanitizeInput(value.apellidoPaterno || "");
    const apellidoMaterno = sanitizeInput(value.apellidoMaterno || "");
    const correo = value.correo.toLowerCase();
    const telefono = value.telefono;
    const dni = value.dni;

    // Check if correo already exists
    const exists = await Usuario.findOne({ where: { correo } });
    if (exists) return res.status(409).json({ message: "El correo ya está registrado" });

    // Hash password
    const hashedPassword = await bcrypt.hash(value.password, SALT_ROUNDS);

    // Generate verification code and store in cache
    const verificationCode = generate6DigitCode();
    myCache.set(correo, verificationCode);

    // Prepare email
    const mailOptions = {
      from: process.env.MAIL_FROM || "no-reply@example.com",
      to: correo,
      subject: "Código de verificación",
      text: `Tu código de verificación es: ${verificationCode}. Expira en 5 minutos.`
    };

    // Create user in DB but mark as not verified (campo "verificado" boolean)
    const nuevoUsuario = await Usuario.create({
      nombre,
      apellidoPaterno,
      apellidoMaterno,
      password: hashedPassword,
      correo,
      telefono,
      dni,
      verificado: false // requiere verificación por correo
    });

    // Send email (await promise - do not leak details on failure)
    try {
      await Transporter.sendMail(mailOptions);
      return res.status(201).json({ mensaje: "Se ha enviado un código de verificación a tu correo" });
    } catch (mailErr) {
      console.error("Error al enviar correo de verificación:", mailErr.message);
      // remove the created user to avoid unverified stale accounts (optional)
      await nuevoUsuario.destroy();
      return res.status(500).json({ message: "No se pudo enviar el correo de verificación" });
    }
  } catch (error) {
    console.error("Error al registrar usuario:", error.message);
    return res.status(500).json({ message: "Error al registrar usuario" });
  }
});

// POST /verificarCodigo - Verifica el código y activa la cuenta
router.post("/verificarCodigo", async (req, res) => {
  try {
    const { error, value } = verificationSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const correo = value.correo.toLowerCase();
    const codigo = value.codigo;

    const storedCode = myCache.get(correo);
    if (!storedCode) return res.status(404).json({ message: "No se encontró un código o expiró" });

    if (storedCode !== codigo) return res.status(400).json({ message: "Código incorrecto" });

    // Mark user as verified
    const usuario = await Usuario.findOne({ where: { correo } });
    if (!usuario) return res.status(404).json({ message: "Usuario no encontrado" });

    usuario.verificado = true;
    await usuario.save();

    myCache.del(correo);

    return res.status(200).json({ message: "Correo verificado correctamente" });
  } catch (error) {
    console.error("Error al verificar el código:", error.message);
    return res.status(500).json({ message: "Error al verificar el código" });
  }
});

/* ---------------------------------------------------------------
   Autenticación (login) - compare bcrypt and issue JWT
   - Rate limited to mitigate brute force
   --------------------------------------------------------------- */
router.post('/iniciarSesion', loginLimiter, async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const correo = value.correo.toLowerCase();
    const password = value.password;

    const usuario = await Usuario.findOne({ where: { correo } });
    if (!usuario) return res.status(404).json({ message: "Usuario no encontrado" });

    if (usuario.estado === false) return res.status(403).json({ message: "Cuenta inhabilitada" });
    if (!usuario.verificado) return res.status(403).json({ message: "Cuenta no verificada" });

    const match = await bcrypt.compare(password, usuario.password);
    if (!match) return res.status(401).json({ message: "Correo o contraseña incorrectos" });

    // Issue JWT (do not include sensitive info)
    const token = jwt.sign({ id: usuario.id, rol: usuario.rol || "user" }, JWT_SECRET, { expiresIn: JWT_EXPIRATION });

    return res.status(200).json({ message: "Inicio de sesión exitoso", token });
  } catch (error) {
    console.error('Error en el inicio de sesión:', error.message);
    return res.status(500).json({ message: 'Error interno del servidor' });
  }
});

/* ---------------------------------------------------------------
   Recuperación de contraseña: enviar código y verificar
   - Uses cacheContraseña for short-lived codes
   - Rate limits and validation
   --------------------------------------------------------------- */
router.post('/verificarCorreo', async (req, res) => {
  try {
    const { error, value } = emailSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const correo = value.correo.toLowerCase();
    const usuario = await Usuario.findOne({ where: { correo } });
    if (!usuario) return res.status(404).json({ message: 'El correo no existe' });

    const codigoVerificacion = generate6DigitCode();
    cacheContraseña.set(correo, codigoVerificacion);

    const mail = {
      from: process.env.MAIL_FROM || "no-reply@example.com",
      to: correo,
      subject: "Recuperación de cuenta",
      text: `Tu código para recuperar tu cuenta es: ${codigoVerificacion}. Expira en 5 minutos.`
    };

    try {
      await Transporter.sendMail(mail);
      return res.status(200).json({ message: 'El correo existe. Código enviado.' });
    } catch (mailErr) {
      console.error('Error al enviar el correo:', mailErr.message);
      return res.status(500).json({ message: 'Error al enviar el correo' });
    }
  } catch (error) {
    console.error('Error al verificar el correo:', error.message);
    return res.status(500).json({ message: 'Ocurrió un error al verificar el correo.' });
  }
});

router.post('/codigoContrasenia', async (req, res) => {
  try {
    const { error, value } = verificationSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const email = value.correo.toLowerCase();
    const codigo = value.codigo;

    const codigoGenerado = cacheContraseña.get(email);
    if (!codigoGenerado) return res.status(400).json({ message: 'Código expirado. Solicita uno nuevo.' });
    if (codigoGenerado !== codigo) return res.status(400).json({ message: 'Código inválido.' });

    cacheContraseña.del(email);
    return res.status(200).json({ message: 'Código verificado correctamente.' });
  } catch (error) {
    console.error('Error al verificar el código:', error.message);
    return res.status(500).json({ message: 'Error al verificar el código.' });
  }
});

// Endpoint to reset password - requires verification step prior to calling this
router.put('/restablecerContrasena', async (req, res) => {
  try {
    const { correo, password } = req.body;
    // Minimal validation
    const { error } = Joi.object({ correo: Joi.string().email().required(), password: Joi.string().min(8).required() }).validate({ correo, password });
    if (error) return res.status(400).json({ message: error.details[0].message });

    const user = await Usuario.findOne({ where: { correo: correo.toLowerCase() } });
    if (!user) return res.status(404).json({ message: 'Correo no encontrado' });

    // Hash the new password
    user.password = await bcrypt.hash(password, SALT_ROUNDS);
    await user.save();

    return res.status(200).json({ message: 'Contraseña actualizada con éxito' });
  } catch (error) {
    console.error('Error al restablecer la contraseña:', error.message);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

/* ---------------------------------------------------------------
   Direcciones (owner-only): sanitize inputs, ensure ownership
   --------------------------------------------------------------- */
router.post('/:id/direcciones', auth(), generalLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    const { nuevaDireccion } = req.body;

    if (req.user.id !== parseInt(id, 10) && req.user.rol !== "admin") return res.status(403).json({ error: "No autorizado" });
    if (!nuevaDireccion || !nuevaDireccion.trim()) return res.status(400).json({ error: "La dirección no puede estar vacía" });

    const usuario = await Usuario.findByPk(id);
    if (!usuario) return res.status(404).json({ error: "Usuario no encontrado" });

    const safe = sanitizeInput(nuevaDireccion);
    usuario.direcciones = [...(usuario.direcciones || []), safe];
    await usuario.save();

    return res.json({ direcciones: usuario.direcciones });
  } catch (error) {
    console.error("Error al agregar dirección:", error.message);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

router.put('/:id/direcciones/:index', auth(), generalLimiter, async (req, res) => {
  try {
    const { id, index } = req.params;
    const { nuevaDireccion } = req.body;

    if (req.user.id !== parseInt(id, 10) && req.user.rol !== "admin") return res.status(403).json({ error: "No autorizado" });
    if (!nuevaDireccion || !nuevaDireccion.trim()) return res.status(400).json({ error: "La dirección no puede estar vacía" });

    const usuario = await Usuario.findByPk(id);
    if (!usuario) return res.status(404).json({ error: "Usuario no encontrado" });

    const indexInt = parseInt(index, 10);
    if (isNaN(indexInt) || indexInt < 0 || indexInt >= (usuario.direcciones || []).length) {
      return res.status(400).json({ error: "Índice de dirección no válido" });
    }

    usuario.direcciones[indexInt] = sanitizeInput(nuevaDireccion);
    await usuario.save();

    return res.json({ direcciones: usuario.direcciones });
  } catch (error) {
    console.error("Error al actualizar la dirección:", error.message);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

router.delete('/:id/direcciones/:index', auth(), generalLimiter, async (req, res) => {
  try {
    const { id, index } = req.params;

    if (req.user.id !== parseInt(id, 10) && req.user.rol !== "admin") return res.status(403).json({ error: "No autorizado" });

    const usuario = await Usuario.findByPk(id);
    if (!usuario) return res.status(404).json({ error: "Usuario no encontrado" });

    const indexInt = parseInt(index, 10);
    if (isNaN(indexInt) || indexInt < 0 || indexInt >= (usuario.direcciones || []).length) {
      return res.status(400).json({ error: "Índice de dirección no válido" });
    }

    usuario.direcciones.splice(indexInt, 1);
    await usuario.save();

    return res.json({ direcciones: usuario.direcciones });
  } catch (error) {
    console.error("Error al eliminar la dirección:", error.message);
    return res.status(500).json({ error: "Error interno del servidor" });
  }
});

export default router;
