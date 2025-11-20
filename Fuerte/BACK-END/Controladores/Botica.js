
import express from "express";
import { Orden, Botica } from "../Models/Relaciones.js";
import { Op } from "sequelize";
import Joi from "joi";
import sanitizeHtml from "sanitize-html";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";

const router = express.Router();

/* ============================================================
   CONFIG
============================================================ */
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_SECURE_KEY";
const JWT_EXPIRATION = "2h";

const limiter = rateLimit({
  windowMs: 1000,
  max: 20,
  message: { message: "Demasiadas solicitudes, espere un momento." }
});

/* ============================================================
   HELPERS
============================================================ */
function sanitize(str) {
  if (typeof str !== "string") return str;
  return sanitizeHtml(str, { allowedTags: [], allowedAttributes: {} }).trim();
}

function auth(required = true) {
  return (req, res, next) => {
    try {
      const header = req.headers.authorization;
      if (!header) {
        if (!required) return next();
        return res.status(401).json({ message: "Token requerido" });
      }

      const token = header.split(" ")[1];
      const payload = jwt.verify(token, JWT_SECRET);
      req.user = payload; // { id, rol, boticaID }

      next();
    } catch {
      return res.status(403).json({ message: "Token inválido o expirado" });
    }
  };
}

function requireRole(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.rol)) {
      return res.status(403).json({ message: "No autorizado" });
    }
    next();
  };
}

/* ============================================================
   VALIDATION SCHEMAS
============================================================ */
const ingresosSchema = Joi.object({
  boticaID: Joi.number().integer().required(),
  fecha: Joi.string()
    .pattern(/^\d{4}-\d{2}-\d{2}$/)
    .required()
});

const boticaSchema = Joi.object({
  ruc: Joi.string().min(11).max(11).required(),
  nombre: Joi.string().min(2).max(200).required(),
  horarioAbre: Joi.string().required(),
  horarioCierre: Joi.string().required(),
  direccion: Joi.string().required(),
  direccion_latitude: Joi.number().allow(null),
  direccion_longitude: Joi.number().allow(null)
});

/* ============================================================
   RUTAS SEGURAS
============================================================ */

/**
 * GET /ingresosBotica/:boticaID/:fecha
 * - Admin: solo puede ver su propia botica
 * - Superadmin: puede ver cualquiera
 */
router.get(
  "/ingresosBotica/:boticaID/:fecha",
  auth(),
  requireRole(["admin", "superadmin"]),
  limiter,
  async (req, res) => {
    try {
      const raw = {
        boticaID: parseInt(req.params.boticaID),
        fecha: sanitize(req.params.fecha)
      };

      const { error, value } = ingresosSchema.validate(raw);
      if (error) return res.status(400).json({ message: error.details[0].message });

      const { boticaID, fecha } = value;

      // Scope check para admin
      if (req.user.rol === "admin" && req.user.boticaID !== boticaID) {
        return res.status(403).json({ message: "No autorizado para ver esta botica" });
      }

      const ordenes = await Orden.findAll({
        where: {
          boticaID,
          fechaRegistro: {
            [Op.between]: [`${fecha} 00:00:00`, `${fecha} 23:59:59`]
          }
        },
        attributes: ["total"]
      });

      if (ordenes.length === 0) {
        return res.status(404).json({
          mensaje: "No se encontraron órdenes para esa fecha."
        });
      }

      const cantidadOrdenes = ordenes.length;
      const ingresosTotales = ordenes.reduce(
        (sum, o) => sum + parseFloat(o.total),
        0
      );

      res.status(200).json({
        boticaID,
        fecha,
        cantidadOrdenes,
        ingresosTotales: ingresosTotales.toFixed(2)
      });
    } catch (error) {
      console.error("Error ingresos botica:", error.message);
      res.status(500).json({ mensaje: "Error interno del servidor" });
    }
  }
);

/**
 * POST /registrarBotica
 * - SOLO superadmin puede registrar boticas
 */
router.post(
  "/registrarBotica",
  auth(),
  requireRole(["superadmin"]),
  limiter,
  async (req, res) => {
    try {
      const bodySanitized = {
        ruc: sanitize(req.body.ruc),
        nombre: sanitize(req.body.nombre),
        horarioAbre: sanitize(req.body.horarioAbre),
        horarioCierre: sanitize(req.body.horarioCierre),
        direccion: sanitize(req.body.direccion),
        direccion_latitude: req.body.direccion_latitude ?? null,
        direccion_longitude: req.body.direccion_longitude ?? null
      };

      const { error, value } = boticaSchema.validate(bodySanitized);
      if (error) return res.status(400).json({ message: error.details[0].message });

      const nueva = await Botica.create(value);

      res.status(201).json({
        mensaje: "Botica registrada exitosamente",
        botica: nueva
      });
    } catch (error) {
      console.error("Error registrar botica:", error.message);
      res.status(500).json({ mensaje: "Error interno del servidor" });
    }
  }
);

export default router;
