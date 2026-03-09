const express = require("express");
const { google } = require("googleapis");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const fetch = require("node-fetch");
const { execSync } = require("child_process");

const app = express();

const CLOUD_FUNCTION_URL = "https://us-central1-relatoresya-notificaciones.cloudfunctions.net/generateToken"; // ✅ URL de la Cloud Function

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || origin.startsWith("http://localhost") || origin === "https://tms.insecap.cl") {
      callback(null, true);
    } else {
      callback(new Error("Acceso no permitido desde este dominio."));
    }
  },
  methods: ["GET"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

// 🛡️ Habilitar CORS solo para el dominio permitido
app.use(cors(corsOptions));

/**
 * 🔑 Obtiene un nuevo Identity Token de Google Cloud automáticamente.
 * @return {Promise<string>} Token de identidad de Google Cloud
 */
async function getIdentityToken() {
  const metadataServerURL =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://us-central1-relatoresya-notificaciones.cloudfunctions.net/generateToken";

  try {
    if (process.env.GOOGLE_CLOUD_PROJECT) {
      // Si corre en Google Cloud, usa metadata.google.internal
      const response = await fetch(metadataServerURL, {
        headers: { "Metadata-Flavor": "Google" },
      });

      if (!response.ok) {
        throw new Error("No se pudo obtener el Identity Token desde metadata server.");
      }
      return await response.text();
    } else {
      // Si corre en local, usa gcloud auth print-identity-token
      console.log("🔹 Ejecutando `gcloud auth print-identity-token` en local...");
      return execSync("gcloud auth print-identity-token").toString().trim();
    }
  } catch (error) {
    console.error("❌ Error obteniendo el Identity Token:", error.message);
    throw error;
  }
}

/**
 * Middleware que obtiene el Identity Token y lo inyecta en la petición.
 */
async function authMiddleware(req, res, next) {
  try {
    const identityToken = await getIdentityToken();
    req.headers["Authorization"] = `Bearer ${identityToken}`;
    console.log("✅ Identity Token agregado automáticamente al header.");
    next();
  } catch (error) {
    return res.status(401).json({
      error: "No autorizado. No se pudo obtener el token de identidad.",
    });
  }
}

/**
 * 📌 Ruta para generar el token OAuth de Firebase Cloud Messaging
 */
app.get("/generate-token", authMiddleware, async (req, res) => {
  try {
    console.log("📌 Recibida solicitud en /generate-token");

    // 📍 Ruta del archivo de credenciales
    const serviceAccountPath = path.resolve(__dirname, "adminkeys.json");

    // 🚨 Verificar si el archivo existe
    if (!fs.existsSync(serviceAccountPath)) {
      console.error("❌ El archivo adminkeys.json no se encuentra.");
      return res.status(500).json({ error: "El archivo adminkeys.json no existe." });
    }

    // 🔑 Leer credenciales del archivo JSON
    const key = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));

    // 🔑 Crear un cliente JWT para autenticación
    const jwtClient = new google.auth.JWT(
      key.client_email,
      null,
      key.private_key,
      ["https://www.googleapis.com/auth/firebase.messaging"]
    );

    // 🔄 Obtener el token OAuth
    const tokens = await jwtClient.authorize();

    console.log("✅ Token generado correctamente");

    // 📩 Devolver respuesta con el token
    return res.json({
      accessToken: tokens.access_token,
      expiresIn: tokens.expiry_date,
    });

  } catch (error) {
    console.error("❌ Error generando el token:", error.message);
    res.status(500).json({ error: "Error al generar el token OAuth" });
  }
});

// 🚀 Iniciar servidor en el puerto 8080
const PORT = 8080;
app.listen(PORT, () => {
  console.log(`✅ Servidor ejecutándose en http://localhost:${PORT}`);
});
