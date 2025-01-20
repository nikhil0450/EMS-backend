import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
    service: 'gmail',  
    auth: {
        user: process.env.MAIL_USER, 
        pass: process.env.MAIL_PASS  
    },
});

transporter.verify((error, success) => {
    if (error) {
        console.error("Error with Nodemailer transporter:", error.message);
    } else {
        console.log("Nodemailer is ready to send emails");
    }
});

export default transporter;
