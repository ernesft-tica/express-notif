const functions = require("firebase-functions");
const {google} = require("googleapis");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

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

const corsMiddleware = cors(corsOptions);

/**
 * 📌 Ruta para generar el token OAuth de Firebase Cloud Messaging
 */
exports.generateToken = functions.https.onRequest(async (req, res) => {
  corsMiddleware(req, res, async () => {
    try {
      console.log("📌 Recibida solicitud en /generate-token");

      const serviceAccountPath = path.resolve(__dirname, "adminkeys.json");

      if (!fs.existsSync(serviceAccountPath)) {
        console.error("❌ El archivo adminkeys.json no se encuentra.");
        return res.status(500).json({
          error: "El archivo adminkeys.json no existe.",
        });
      }

      const key = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));

      const jwtClient = new google.auth.JWT(
          key.client_email,
          null,
          key.private_key,
          ["https://www.googleapis.com/auth/firebase.messaging"],
      );

      const tokens = await jwtClient.authorize();

      return res.json({
        accessToken: tokens.access_token,
        expiresIn: tokens.expiry_date,
      });
    } catch (error) {
      console.error("❌ Error generando el token:", error.message);
      res.status(500).json({error: "Error al generar el token OAuth"});
    }
  });
});
