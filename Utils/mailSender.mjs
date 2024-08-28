import nodemailer from 'nodemailer';

// Create a transporter using Gmail
const transporter = nodemailer.createTransport({
    service: 'gmail',
    host: "smtp.gmail.com",
    port: 465, // Use port 465 for secure connection
    secure: true,
    auth: {
        user: "khvtisozedelashvili@gmail.com",
        pass: "twna apqf hwdb ufxa",
    },
});

// HTML email template with a verification link
const mailOptions = (toEmail, token) => ({
    from: {
        name: "Blog API Author",
        address: "khvtisozedelashvili@gmail.com"
    },
    to: toEmail,
    subject: "Please Verify Your Email",
    html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px;">
            <div style="text-align: center;">
                <h2 style="color: #333333; margin-bottom: 20px;">Hello!</h2>
                <p style="font-size: 16px; color: #555555; line-height: 1.5; margin-bottom: 30px;">Thank you for signing up. Please confirm your email address to activate your account.</p>
                <a href="https://avatarzone-api.onrender.com/confirm/${token}" style="display: inline-block; padding: 12px 24px; background-color: #4CAF50; color: #ffffff; text-decoration: none; border-radius: 5px; font-size: 16px;">Verify Email</a>
                <p style="font-size: 14px; color: #999999; margin-top: 30px;">If you did not register for this account, please ignore this email.</p>
            </div>
            <div style="margin-top: 40px; text-align: center; font-size: 12px; color: #aaaaaa; border-top: 1px solid #e0e0e0; padding-top: 20px;">
                <p>API Author</p>
                <p>Khvtiso Zedelashvili</p>
            </div>
        </div>
    `
});

// Send email function
const sendEmail = async (toEmail, token) => {
    try {
        await transporter.sendMail(mailOptions(toEmail, token));
        console.log("Email sent!");
    } catch (error) {
        console.error("Error sending email:", error);
    }
}

export default sendEmail;
