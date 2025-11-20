import nodemailer from 'nodemailer';

// Configurar el transporte de Nodemailer para Gmail
const Transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
        user: "lll", // Tu cuenta de Gmail
        pass: "lll" // Contraseña de aplicación generada
    }
});

// Verificar transporte solo si no estás en modo de prueba
if (process.env.NODE_ENV !== 'test') {
    Transporter.verify()
        .then(() => {
            console.log("Listo para enviar emails");
        })
        .catch(err => console.error("Error verificando el transporte:", err));
}

export default Transporter;