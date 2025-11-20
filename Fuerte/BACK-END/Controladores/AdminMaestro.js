import express from 'express';
import { AdminMaestro, Admin, Botica, Usuario } from "../Models/Relaciones.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import Joi from 'joi';
import sanitizeHtml from 'sanitize-html';

const router = express.Router();


const JWT_SECRET = process.env.JWT_SECRET || 'please_set_a_long_secret_in_env';
const JWT_EXPIRATION = process.env.JWT_EXPIRATION || '2h';
const SALT_ROUNDS = Number(process.env.SALT_ROUNDS) || 12;

// Rate limiters
const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 6, message: { message: 'Demasiados intentos, espere un momento.' } });
const generalLimiter = rateLimit({ windowMs: 1000, max: 25 });

// Validation schemas
const loginSchema = Joi.object({ correo: Joi.string().email().required(), password: Joi.string().min(8).max(128).required() });

// minimal sanitize helper
function sanitize(value) {
  if (typeof value !== 'string') return value;
  return sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} }).trim();
}

// auth middleware to validate Bearer token
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
      req.user = payload; // { id, rol, iat, exp }
      return next();
    } catch (err) {
      return res.status(403).json({ message: 'Token inválido o expirado' });
    }
  };
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ message: 'No autenticado' });
    if (req.user.rol !== role) return res.status(403).json({ message: 'Acceso restringido' });
    next();
  };
}


router.post('/iniciarSesionSuperAdmin', authLimiter, async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const correo = sanitize(value.correo).toLowerCase();
    const { password } = value;

    const superAdmin = await AdminMaestro.findOne({ where: { correo } });
    if (!superAdmin) return res.status(401).json({ message: 'Credenciales inválidas' });

    // Compare hashed password
    const match = await bcrypt.compare(password, superAdmin.password);
    if (!match) return res.status(401).json({ message: 'Credenciales inválidas' });

    // Issue JWT with minimal claims
    const token = jwt.sign({ id: superAdmin.id, rol: 'superadmin' }, JWT_SECRET, { expiresIn: JWT_EXPIRATION });

    return res.json({ message: 'Inicio de sesión exitoso', token, admin: { id: superAdmin.id, nombre: superAdmin.nombre, apellidoPaterno: superAdmin.apellidoPaterno, dni: superAdmin.dni, esSuperAdmin: true } });
  } catch (error) {
    console.error('Error en iniciarSesionSuperAdmin:', error.message);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

// GET /estadisticasSuperAdmin - solo superadmin
router.get('/estadisticasSuperAdmin', auth(), requireRole('superadmin'), generalLimiter, async (req, res) => {
  try {
    const totalUsuarios = await Usuario.count();
    const totalBoticas = await Botica.count();
    const totalAdmins = await Admin.count();

    return res.json({ usuarios: totalUsuarios, boticas: totalBoticas, administradores: totalAdmins });
  } catch (error) {
    console.error('Error al obtener estadísticas:', error.message);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

// GET /obtenerAdminsMaestros - solo superadmin
router.get('/obtenerAdminsMaestros', auth(), requireRole('superadmin'), generalLimiter, async (req, res) => {
  try {
    const adminsMaestros = await AdminMaestro.findAll({ attributes: { exclude: ['password'] } });
    if (!adminsMaestros || adminsMaestros.length === 0) return res.status(404).json({ message: 'No se encontraron administradores maestros' });
    return res.json(adminsMaestros);
  } catch (error) {
    console.error('Error al obtener administradores maestros:', error.message);
    return res.status(500).json({ message: 'Error en el servidor' });
  }
});

// GET /listaUsuarios - admin o superadmin (no devolvemos passwords)
router.get('/listaUsuarios', auth(), async (req, res) => {
  try {
    // allow admin and superadmin
    if (!req.user || (req.user.rol !== 'admin' && req.user.rol !== 'superadmin')) return res.status(403).json({ message: 'Acceso restringido' });

    const usuarios = await Usuario.findAll({ attributes: { exclude: ['password'] } });
    return res.json(usuarios);
  } catch (error) {
    console.error('Error al obtener los usuarios:', error.message);
    return res.status(500).json({ error: 'Error al obtener los usuarios' });
  }
});

// GET /listaAdmins - admin or superadmin
router.get('/listaAdmins', auth(), async (req, res) => {
  try {
    if (!req.user || (req.user.rol !== 'admin' && req.user.rol !== 'superadmin')) return res.status(403).json({ message: 'Acceso restringido' });

    const admins = await Admin.findAll({ include: { model: Botica, attributes: ['id', 'nombre', 'ruc', 'estado'] }, attributes: { exclude: ['password'] } });
    return res.json(admins);
  } catch (error) {
    console.error('Error al obtener los administradores:', error.message);
    return res.status(500).json({ error: 'Error al obtener los administradores' });
  }
});

// PUT /cambiarEstadoAdmin/:id - solo superadmin
router.put('/cambiarEstadoAdmin/:id', auth(), requireRole('superadmin'), generalLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    const admin = await Admin.findByPk(id);
    if (!admin) return res.status(404).json({ mensaje: 'Administrador no encontrado' });

    admin.estado = !admin.estado;
    await admin.save();

    return res.json({ mensaje: 'Estado actualizado con éxito', estadoActual: admin.estado });
  } catch (error) {
    console.error('Error al cambiar estado admin:', error.message);
    return res.status(500).json({ mensaje: 'Error al actualizar el estado' });
  }
});

// PUT /cambiarEstadoUsuario/:id - superadmin or admin can toggle (but admin only within their botica)
router.put('/cambiarEstadoUsuario/:id', auth(), generalLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    const requester = req.user;
    if (!requester) return res.status(401).json({ message: 'No autenticado' });

    const usuario = await Usuario.findByPk(id);
    if (!usuario) return res.status(404).json({ mensaje: 'Usuario no encontrado' });

    // If requester is admin, optionally enforce scope (example: only allow admins to toggle users related to their botica)
    if (requester.rol === 'admin') {
      // if Admin model stores boticaID, we could check ownership. This is placeholder logic and should be adapted.
      const admin = await Admin.findOne({ where: { id: requester.id } });
      if (!admin) return res.status(403).json({ message: 'Admin no encontrado o sin permisos' });
      // Example check (uncomment and adapt if Usuario has boticaID relation)
      // if (usuario.boticaID !== admin.boticaID) return res.status(403).json({ message: 'No autorizado para modificar este usuario' });
    } else if (requester.rol !== 'superadmin') {
      return res.status(403).json({ message: 'Acceso restringido' });
    }

    usuario.estado = !usuario.estado;
    await usuario.save();

    return res.json({ mensaje: 'Estado actualizado con éxito', estadoActual: usuario.estado });
  } catch (error) {
    console.error('Error al cambiar estado usuario:', error.message);
    return res.status(500).json({ mensaje: 'Error al actualizar el estado' });
  }
});

export default router;
