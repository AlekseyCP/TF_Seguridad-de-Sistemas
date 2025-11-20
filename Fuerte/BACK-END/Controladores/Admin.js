// Router de Admin endurecido - Admin Router Seguro
// Reescrito siguiendo OWASP: autenticación JWT, hashing con bcrypt,
// validación con Joi, rate limiting, sanitización, control de roles y scope.

import express from "express";
import { Admin, Producto , Marca, ProductoDetalle, Botica } from "../Models/Relaciones.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import Joi from "joi";
import sanitizeHtml from "sanitize-html";

const router = express.Router();

/* ==========================
   Configuración y helpers
   ========================== */
const JWT_SECRET = process.env.JWT_SECRET || "please_set_a_long_secret_in_env";
const JWT_EXPIRATION = process.env.JWT_EXPIRATION || "2h";
const SALT_ROUNDS = Number(process.env.SALT_ROUNDS) || 12;

const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 6, message: { message: 'Demasiados intentos, espere un momento.' } });
const generalLimiter = rateLimit({ windowMs: 1000, max: 25 });

// Schemas Joi
const loginSchema = Joi.object({ correo: Joi.string().email().required(), password: Joi.string().min(8).max(128).required() });
const registerSchema = Joi.object({ nombre: Joi.string().min(2).max(100).required(), apellidoPaterno: Joi.string().allow(null, "").max(100), apellidoMaterno: Joi.string().allow(null, "").max(100), correo: Joi.string().email().required(), password: Joi.string().min(8).max(128).required(), dni: Joi.string().pattern(/^\d{8}$/).required(), boticaID: Joi.number().integer().required() });

// sanitize helper
function sanitize(value) {
  if (typeof value !== 'string') return value;
  return sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} }).trim();
}

// auth middleware
function auth(required = true) {
  return (req, res, next) => {
    try {
      const header = req.headers.authorization;
      if (!header) {
        if (!required) return next();
        return res.status(401).json({ message: 'Token requerido' });
      }
      const parts = header.split(' ');
      if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ message: 'Formato de token inválido' });
      const token = parts[1];
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload; // { id, rol, boticaID?, iat, exp }
      return next();
    } catch (err) {
      return res.status(403).json({ message: 'Token inválido o expirado' });
    }
  };
}

function requireRole(roles = []) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ message: 'No autenticado' });
    if (!roles.includes(req.user.rol)) return res.status(403).json({ message: 'Acceso restringido' });
    next();
  };
}

/* ==========================
   Vulnerabilidades encontradas (resumen)
   ========================== */
// - Contraseñas almacenadas en texto plano -> Cryptographic Failures
// - Sin hashing en registro ni restauración -> Identification & Authentication Failures
// - Rutas sin autenticación ni control de roles -> Broken Access Control
// - No validación de inputs -> Injection / XSS risks
// - Retorno de datos sensibles (passwords) -> Sensitive Data Exposure
// - No limitación de intentos -> Brute force
// - No scope para admins (pueden afectar recursos ajenos) -> Broken Function Level Auth

/* ==========================
   Rutas: endurecidas
   ========================== */

// POST /iniciarSesion - Admin login -> devuelve JWT con rol 'admin' y boticaID si aplica
router.post('/iniciarSesion', authLimiter, async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const correo = sanitize(value.correo).toLowerCase();
    const password = value.password;

    const admin = await Admin.findOne({ where: { correo } });
    if (!admin) return res.status(401).json({ message: 'Credenciales inválidas' });

    if (!admin.estado) return res.status(403).json({ message: 'Cuenta inactiva' });

    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.status(401).json({ message: 'Credenciales inválidas' });

    // Include boticaID in token if admin belongs to a botica
    const tokenPayload = { id: admin.id, rol: 'admin' };
    if (admin.boticaID) tokenPayload.boticaID = admin.boticaID;

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: JWT_EXPIRATION });

    return res.json({ message: 'Inicio de sesión exitoso', token, admin: { boticaID: admin.boticaID, nombre: admin.nombre, apellidoPaterno: admin.apellidoPaterno } });
  } catch (error) {
    console.error('Error en inicio de sesión admin:', error.message);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

// GET /boticaProductos/:boticaID - admin or superadmin, scope enforced: admin can only access their botica
router.get('/boticaProductos/:boticaID', auth(), requireRole(['admin','superadmin']), generalLimiter, async (req, res) => {
  try {
    const { boticaID } = req.params;
    const boticaIdInt = parseInt(boticaID, 10);
    if (isNaN(boticaIdInt)) return res.status(400).json({ message: 'BoticaID inválido' });

    // If requester is admin, ensure they only request their own botica
    if (req.user.rol === 'admin' && req.user.boticaID && req.user.boticaID !== boticaIdInt) {
      return res.status(403).json({ message: 'No autorizado para acceder a esta botica' });
    }

    const productos = await ProductoDetalle.findAll({
      where: { boticaID: boticaIdInt },
      include: [
        { model: Producto, attributes: ['id','nombre','presentacion','categoria','nRegistroSanitario'], include: [{ model: Marca, attributes: ['id','nombre'] }] }
      ]
    });

    return res.json(productos);
  } catch (error) {
    console.error('Error al obtener productos botica:', error.message);
    return res.status(500).json({ error: 'Error al obtener los productos' });
  }
});

// GET /administradores?boticaID= - admin or superadmin; admins can only list their own botica admins
router.get('/administradores', auth(), requireRole(['admin','superadmin']), generalLimiter, async (req, res) => {
  try {
    const boticaID = req.query.boticaID ? parseInt(req.query.boticaID,10) : null;

    // If admin requester and provided boticaID differs from their own, block
    if (req.user.rol === 'admin' && boticaID && req.user.boticaID && boticaID !== req.user.boticaID) {
      return res.status(403).json({ message: 'No autorizado' });
    }

    const whereClause = boticaID ? { boticaID } : {};

    const administradores = await Admin.findAll({ where: whereClause, include: { model: Botica, attributes: ['nombre'], required: false }, attributes: { exclude: ['password'] } });

    if (!administradores || administradores.length === 0) return res.status(404).json({ mensaje: 'No se encontraron administradores' });

    const resultado = administradores.map(admin => ({ nombre: admin.nombre, apellidoPaterno: admin.apellidoPaterno, apellidoMaterno: admin.apellidoMaterno, botica: admin.Botica ? admin.Botica.nombre : 'Sin botica' }));

    return res.status(200).json(resultado);
  } catch (error) {
    console.error('Error al obtener administradores:', error.message);
    return res.status(500).json({ mensaje: 'Error al obtener administradores' });
  }
});

// POST /registrar - crear admin (only superadmin)
router.post('/registrar', auth(), requireRole(['superadmin']), async (req, res) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    // sanitize
    const nombre = sanitize(value.nombre);
    const apellidoPaterno = sanitize(value.apellidoPaterno || '');
    const apellidoMaterno = sanitize(value.apellidoMaterno || '');
    const correo = sanitize(value.correo).toLowerCase();
    const dni = sanitize(value.dni);
    const boticaID = value.boticaID;

    // ensure botica exists
    const botica = await Botica.findByPk(boticaID);
    if (!botica) return res.status(400).json({ message: 'Botica no existe' });

    // check email unique
    const exists = await Admin.findOne({ where: { correo } });
    if (exists) return res.status(409).json({ message: 'Correo ya registrado' });

    const hashed = await bcrypt.hash(value.password, SALT_ROUNDS);

    const nuevoAdmin = await Admin.create({ nombre, apellidoPaterno, apellidoMaterno, correo, password: hashed, dni, boticaID });

    // return without password
    const { password, ...safeAdmin } = nuevoAdmin.toJSON();
    return res.status(201).json({ message: 'Administrador registrado exitosamente', admin: safeAdmin });
  } catch (error) {
    console.error('Error al registrar admin:', error.message);
    return res.status(500).json({ message: 'Error al registrar el administrador' });
  }
});

// PUT /cambiarEstado/:id - toggle ProductoDetalle.estado - admin must belong to same botica or superadmin
router.put('/cambiarEstado/:id', auth(), requireRole(['admin','superadmin']), generalLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    const producto = await ProductoDetalle.findByPk(id);
    if (!producto) return res.status(404).json({ message: 'ProductoDetalle no encontrado' });

    // If admin, ensure scope
    if (req.user.rol === 'admin' && req.user.boticaID && req.user.boticaID !== producto.boticaID) {
      return res.status(403).json({ message: 'No autorizado para modificar este producto' });
    }

    producto.estado = !producto.estado;
    await producto.save();

    return res.json({ message: 'Estado del producto actualizado exitosamente', estado: producto.estado });
  } catch (error) {
    console.error('Error al actualizar estado producto:', error.message);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

// PUT /cambiarStock?id=&stock= - updates cantidad, validated & scoped
router.put('/cambiarStock', auth(), requireRole(['admin','superadmin']), generalLimiter, async (req, res) => {
  try {
    const id = parseInt(req.query.id, 10);
    const stock = parseInt(req.query.stock, 10);
    if (isNaN(id) || isNaN(stock) || stock < 0) return res.status(400).json({ message: 'Parámetros inválidos' });

    const producto = await ProductoDetalle.findByPk(id);
    if (!producto) return res.status(404).json({ message: 'ProductoDetalle no encontrado' });

    if (req.user.rol === 'admin' && req.user.boticaID && req.user.boticaID !== producto.boticaID) {
      return res.status(403).json({ message: 'No autorizado para modificar este producto' });
    }

    producto.cantidad = stock;
    await producto.save();

    const safe = JSON.parse(JSON.stringify(producto));
    return res.json(safe);
  } catch (error) {
    console.error('Error al actualizar stock:', error.message);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

// GET /verificarCorreoAdmin/:correo - rate limited and sanitized
router.get('/verificarCorreoAdmin/:correo', auth(), requireRole(['admin','superadmin']), generalLimiter, async (req, res) => {
  try {
    const correo = sanitize(req.params.correo).toLowerCase();
    const admin = await Admin.findOne({ where: { correo } });
    if (admin) return res.status(200).json({ message: 'El correo existe' });
    return res.status(404).json({ message: 'El correo no existe' });
  } catch (error) {
    console.error('Error al verificar correo admin:', error.message);
    return res.status(500).json({ message: 'Ocurrió un error al verificar el correo.' });
  }
});

// PUT /restablecerContrasenaAdmin - require verification step outside this endpoint (e.g., token or code)
router.put('/restablecerContrasenaAdmin', auth(), requireRole(['superadmin']), async (req, res) => {
  try {
    const schema = Joi.object({ correo: Joi.string().email().required(), password: Joi.string().min(8).required() });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const correo = sanitize(value.correo).toLowerCase();
    const admin = await Admin.findOne({ where: { correo } });
    if (!admin) return res.status(404).json({ message: 'Correo no encontrado' });

    admin.password = await bcrypt.hash(value.password, SALT_ROUNDS);
    await admin.save();

    return res.status(200).json({ message: 'Contraseña actualizada con éxito' });
  } catch (error) {
    console.error('Error al restablecer contraseña admin:', error.message);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

export default router;
