const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const nodemailer = require('nodemailer');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config(); // Must be at the very top
const { google } = require('googleapis');

// --- File Upload Setup (Multer) ---
// Define the path where uploaded avatars will be stored
const avatarUploadPath = path.join(__dirname, 'public', 'uploads', 'avatars');
// Create the directory if it doesn't already exist
if (!fs.existsSync(avatarUploadPath)) {
    fs.mkdirSync(avatarUploadPath, { recursive: true });
}

// Configure how files are stored on the server's disk
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, avatarUploadPath);
    },
    filename: (req, file, cb) => {
        // Create a unique filename to prevent overwrites: userId-timestamp.extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `${req.user.id}-${uniqueSuffix}${path.extname(file.originalname)}`);
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB file size limit
    fileFilter: (req, file, cb) => {
        // Allow only specific image file types (jpeg, jpg, png, gif)
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error("Error: File upload only supports jpeg, jpg, png, and gif formats."));
    }
});

// --- Nodemailer Setup ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com', port: 587, secure: false,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});
console.log('Nodemailer transporter configured.');

// --- Google OAuth2 Client ---
// This client will be used to interact with the Google Calendar API
const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
);

// --- Core App Setup ---
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
// Serve uploaded avatars statically so they can be accessed from the browser via a URL
app.use('/uploads/avatars', express.static(avatarUploadPath));


// --- PostgreSQL Connection ---
// CRITICAL FIX: Use the single DATABASE_URL connection string from the .env file.
// This is the correct method for connecting to Neon, as it handles SSL automatically.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});
console.log('PostgreSQL Connection Pool created.');

// --- In-Memory OTP Storage ---
const otpStore = {};

// --- Helper function to validate appointment times against business rules ---
const isAppointmentTimeValid = (date, time) => {
    // Combine date and time to create a valid Date object in UTC to avoid timezone issues.
    const appointmentDate = new Date(`${date}T${time}:00.000Z`);

    // getUTCDay() returns 0 for Sunday, 6 for Saturday.
    const dayOfWeek = appointmentDate.getUTCDay();
    if (dayOfWeek === 0 || dayOfWeek === 6) {
        return false; // It's a weekend.
    }

    // String comparison works reliably for 'HH:MM' format.
    if (time < '09:00' || time > '17:00') {
        return false; // It's outside business hours.
    }

    return true; // The time is valid.
};

// --- Database Setup Function ---
async function setupDatabase() {
    console.log('---!! RUNNING DATABASE SETUP !!---');
    const client = await pool.connect();
    try {
        const setupQuery = `
            DROP TABLE IF EXISTS appointments;
            DROP TABLE IF EXISTS faculty_profiles;
            DROP TABLE IF EXISTS users;

            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                avatar_url VARCHAR(255),
                year_semester VARCHAR(100),
                department VARCHAR(255),
                designation VARCHAR(255),
                office VARCHAR(255),
                phone VARCHAR(20),
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE faculty_profiles (
                user_id INT PRIMARY KEY,
                availability JSONB DEFAULT '{}'::jsonb,
                google_refresh_token TEXT,
                CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE appointments (
                id SERIAL PRIMARY KEY,
                student_id INT NOT NULL,
                faculty_id INT NOT NULL,
                purpose TEXT NOT NULL,
                date VARCHAR(50) NOT NULL,
                time VARCHAR(50) NOT NULL,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                CONSTRAINT fk_student FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
                CONSTRAINT fk_faculty FOREIGN KEY(faculty_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX idx_appointments_student_id ON appointments(student_id);
            CREATE INDEX idx_appointments_faculty_id ON appointments(faculty_id);
        `;
        await client.query(setupQuery);
        console.log('Tables created successfully.');

        const salt = await bcrypt.genSalt(10);
        const facultyPasswordHash = await bcrypt.hash('password', salt);
        const studentPasswordHash = await bcrypt.hash('password', salt);

        const facultyResult = await client.query(
            `INSERT INTO users (name, email, password, role, department, designation, office, phone)
             VALUES ($1, $2, $3, 'faculty', 'Computer Science Engineering', 'Professor', 'Block IV - S01', '1234567890')
             RETURNING id`,
            ['Dr. Muzafar Rasool', 'm.rasool@i.com', facultyPasswordHash]
        );
        console.log('Faculty user inserted.');

        await client.query(
            `INSERT INTO users (name, email, password, role, department, year_semester, phone)
             VALUES ($1, $2, $3, 'student', 'Computer Science Engineering', '3rd Year', '0987654321')`,
            ['Syed Afaan', 'afaan@s.com', studentPasswordHash]
        );
        console.log('Student user inserted.');

        const defaultAvailability = JSON.stringify({
            "monday": ["09:00", "10:00", "11:00"], "tuesday": ["14:00", "15:00"],
            "wednesday": ["09:00", "10:00", "11:00", "12:00"], "thursday": [],
            "friday": ["14:00", "15:00", "16:00"]
        });

        await client.query(
            'INSERT INTO faculty_profiles (user_id, availability) VALUES ($1, $2)',
            [facultyResult.rows[0].id, defaultAvailability]
        );
        console.log('Faculty profile created with default availability.');

        console.log('---!! DATABASE SETUP COMPLETE !!---');
    } catch (error) {
        console.error('---!! DATABASE SETUP FAILED !!---', error);
    } finally {
        client.release();
    }
}

// --- Middleware to verify JWT token ---
const authMiddleware = (req, res, next) => {
    let token = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }
    // Fallback for cases where token is passed as a query parameter (e.g., links)
    else if (req.query.token) {
        token = req.query.token;
    }

    if (!token) {
        return res.status(401).json({ message: 'Authorization denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Add user payload (id, name, email, role) to the request object
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid.' });
    }
};

// --- AUTHENTICATION & REGISTRATION APIS ---
app.post('/api/auth/login', async (req, res) => {
    const { email, password, role } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user || user.role !== role) {
            return res.status(401).json({ message: 'Invalid credentials or role mismatch.' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const payload = { id: user.id, name: user.name, email: user.email, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '3h' });
        delete user.password; // Never send the password hash back to the client
        res.json({ message: 'Login successful', token, user });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.post('/api/auth/send-otp', async (req, res) => {
    const { email } = req.body;
    try {
        const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ message: 'User with this email already exists.' });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };
        const mailOptions = { from: process.env.EMAIL_USER, to: email, subject: 'Your OTP for IUST Appointment Portal', text: `Your One-Time Password is: ${otp}\n\nThis OTP is valid for 5 minutes.` };
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'OTP sent successfully to your email.' });
    } catch (error) {
        console.error('Error in send-otp:', error);
        res.status(500).json({ message: 'Error sending OTP. Please try again later.' });
    }
});
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, phone, role, department, yearSemester: year_semester, designation, office, otp } = req.body;
    try {
        const storedOtpData = otpStore[email];
        if (!storedOtpData || Date.now() > storedOtpData.expires || storedOtpData.otp !== otp) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            const query = role === 'student' ?
                `INSERT INTO users (name, email, password, role, department, year_semester, phone) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *` :
                `INSERT INTO users (name, email, password, role, department, designation, office, phone) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`;
            const values = role === 'student' ?
                [name, email, hashedPassword, role, department, year_semester, phone] :
                [name, email, hashedPassword, role, department, designation, office, phone];
            const result = await client.query(query, values);
            const newUser = result.rows[0];
            if (role === 'faculty') {
                await client.query('INSERT INTO faculty_profiles (user_id) VALUES ($1)', [newUser.id]);
            }
            await client.query('COMMIT');
            delete otpStore[email];
            res.status(201).json({ message: 'Registration successful' });
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Registration transaction error:', error);
            if (error.code === '23505') return res.status(400).json({ message: 'User with this email already exists.' });
            res.status(500).json({ message: 'Registration failed due to a server error.' });
        } finally {
            client.release();
        }
    } catch (error) {
        console.error('General registration error:', error);
        res.status(500).json({ message: 'Registration failed' });
    }
});


// --- FACULTY & PROFILE APIS ---
app.get('/api/faculty', authMiddleware, async (req, res) => {
    try {
        let query = "SELECT id, name, email, department, designation, office, avatar_url FROM users WHERE role = 'faculty'";
        const queryParams = [];
        if (req.user.role === 'faculty') {
            query += " AND id != $1";
            queryParams.push(req.user.id);
        }
        const result = await pool.query(query, queryParams);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching faculty:', error);
        res.status(500).json({ message: 'Error fetching faculty directory.' });
    }
});

app.get('/api/faculty/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(`
            SELECT u.id, u.name, u.email, u.department, u.designation, u.office, u.avatar_url, fp.availability
            FROM users u LEFT JOIN faculty_profiles fp ON u.id = fp.user_id
            WHERE u.id = $1 AND u.role = 'faculty'`, [id]
        );
        if (result.rows.length === 0) return res.status(404).json({ message: 'Faculty not found.' });
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching faculty profile:', error);
        res.status(500).json({ message: 'Error fetching faculty profile.' });
    }
});

app.get('/api/users/profile', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(`SELECT u.*, fp.availability, fp.google_refresh_token FROM users u LEFT JOIN faculty_profiles fp ON u.id = fp.user_id WHERE u.id = $1`, [req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'User not found.' });
        delete result.rows[0].password;
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Error fetching profile.' });
    }
});

app.put('/api/users/profile', authMiddleware, async (req, res) => {
    const { name, phone, department, yearSemester, designation, office } = req.body;
    try {
        const result = await pool.query( `UPDATE users SET name = $1, phone = $2, department = $3, year_semester = $4, designation = $5, office = $6 WHERE id = $7 RETURNING *`,
            [name, phone, department, yearSemester, designation, office, req.user.id]
        );
        const updatedUser = result.rows[0];
        delete updatedUser.password;
        res.json({ message: 'Profile updated successfully!', user: updatedUser });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ message: 'Error updating profile.' });
    }
});

app.post('/api/users/profile/avatar', authMiddleware, upload.single('avatar'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
        const avatarUrl = `/uploads/avatars/${req.file.filename}`;
        const oldData = await pool.query('SELECT avatar_url FROM users WHERE id = $1', [req.user.id]);
        if (oldData.rows.length > 0 && oldData.rows[0].avatar_url) {
            const oldPath = path.join(__dirname, 'public', oldData.rows[0].avatar_url);
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }
        await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [avatarUrl, req.user.id]);
        res.json({ message: 'Profile picture updated successfully!', avatarUrl });
    } catch (error) {
        console.error('Error uploading avatar:', error);
        res.status(500).json({ message: `Error uploading avatar: ${error.message}` });
    }
});

app.put('/api/faculty/profile/availability', authMiddleware, async (req, res) => {
    if (req.user.role !== 'faculty') { return res.status(403).json({ message: 'Permission denied. This action is for faculty only.' }); }
    try {
        const { availability } = req.body;
        if (typeof availability !== 'object' || availability === null) { return res.status(400).json({ message: 'Invalid availability data format.' }); }
        const availabilityJson = JSON.stringify(availability);
        const result = await pool.query('UPDATE faculty_profiles SET availability = $1 WHERE user_id = $2 RETURNING user_id', [availabilityJson, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'Faculty profile not found.' });
        res.json({ message: 'Availability updated successfully!' });
    } catch (error) {
        console.error('Error updating availability:', error);
        res.status(500).json({ message: 'Error updating availability.' });
    }
});

// --- GOOGLE CALENDAR & APPOINTMENT APIS ---
app.get('/api/auth/google', authMiddleware, (req, res) => {
    // This endpoint initiates the Google OAuth flow for a faculty member.
    if (req.user.role !== 'faculty') {
        return res.status(403).send('Only faculty can link their Google Calendar.');
    }
    const scopes = ['https://www.googleapis.com/auth/calendar.events'];
    const url = oauth2Client.generateAuthUrl({
        access_type: 'offline', // Request a refresh token for long-term access
        scope: scopes,
        state: req.user.id.toString() // Pass the user's ID to identify them in the callback
    });
    res.redirect(url);
});

app.get('/api/auth/google/callback', async (req, res) => {
    // Google redirects here after the user grants permission.
    const { code, state: userId } = req.query;
    try {
        const { tokens } = await oauth2Client.getToken(code);
        const refreshToken = tokens.refresh_token;

        if (!refreshToken) {
            return res.status(400).send('Could not get a refresh token from Google. Please remove app access from your Google account settings and try again.');
        }

        // Securely store the refresh token in the database for the specific faculty member.
        await pool.query('UPDATE faculty_profiles SET google_refresh_token = $1 WHERE user_id = $2', [refreshToken, parseInt(userId, 10)]);
        res.redirect('/#profile'); // Redirect the user back to their profile page.
    } catch (error) {
        console.error('Error during Google OAuth callback:', error);
        res.status(500).send('Failed to authenticate with Google.');
    }
});

app.get('/api/appointments', authMiddleware, async (req, res) => {
    try {
        const { id: userId, role } = req.user;
        let queryText = `
            SELECT a.id, a.purpose, a.date, a.time, a.status,
                   s.id as "studentId", s.name AS "studentName", s.email AS "studentEmail", s.role AS "studentRole",
                   f.id as "facultyId", f.name AS "facultyName", f.email as "facultyEmail"
            FROM appointments a
            JOIN users s ON a.student_id = s.id
            JOIN users f ON a.faculty_id = f.id
        `;
        const queryParams = [];

        // Faculty can now book appointments with other faculty, so their view shows all appointments they are involved in.
        if (role === 'faculty') {
            queryText += ' WHERE (a.student_id = $1 OR a.faculty_id = $1) ORDER BY a.created_at DESC';
            queryParams.push(userId);
        } else { // Students see only the appointments they have booked.
            queryText += ' WHERE a.student_id = $1 ORDER BY a.created_at DESC';
            queryParams.push(userId);
        }

        const result = await pool.query(queryText, queryParams);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching appointments:', error);
        res.status(500).json({ message: 'Error fetching appointments.' });
    }
});

app.post('/api/appointments', authMiddleware, async (req, res) => {
    const { facultyId, purpose, date, time } = req.body;

    if (!isAppointmentTimeValid(date, time)) {
        return res.status(400).json({ message: 'Appointments can only be scheduled on weekdays between 9:00 AM and 5:00 PM.' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO appointments (student_id, faculty_id, purpose, date, time, status) VALUES ($1, $2, $3, $4, $5, 'pending') RETURNING *`,
            [req.user.id, facultyId, purpose, date, time]
        );
        const newAppointment = result.rows[0];
        res.status(201).json({ message: 'Appointment created successfully', appointment: newAppointment });

        // Create Google Calendar event in the background without blocking the response
        createGoogleCalendarEvent(newAppointment, req.user.id, facultyId)
            .catch(calendarError => console.error('Failed to create Google Calendar event in the background:', calendarError));

    } catch (error) {
        console.error('Error creating appointment:', error);
        res.status(500).json({ message: 'Error creating appointment.' });
    }
});

async function createGoogleCalendarEvent(appointment, studentId, facultyId) {
    try {
        const facultyProfile = await pool.query('SELECT fp.google_refresh_token, u.email FROM faculty_profiles fp JOIN users u ON fp.user_id = u.id WHERE fp.user_id = $1', [facultyId]);
        const refreshToken = facultyProfile.rows[0]?.google_refresh_token;
        const facultyEmail = facultyProfile.rows[0]?.email;
        
        if (refreshToken && facultyEmail) {
            oauth2Client.setCredentials({ refresh_token: refreshToken });
            const calendar = google.calendar({ version: 'v3', auth: oauth2Client });

            const student = await pool.query('SELECT name, email FROM users WHERE id = $1', [studentId]);
            const studentName = student.rows[0].name;
            const studentEmail = student.rows[0].email;
            
            const startTime = new Date(`${appointment.date}T${appointment.time}:00`);
            const endTime = new Date(startTime.getTime() + 30 * 60000); // Assume 30-minute duration

            const event = {
                summary: `Appointment: ${studentName}`,
                description: `Purpose: ${appointment.purpose}`,
                start: { dateTime: startTime.toISOString(), timeZone: 'Asia/Kolkata' },
                end: { dateTime: endTime.toISOString(), timeZone: 'Asia/Kolkata' },
                attendees: [{ 'email': facultyEmail }, { 'email': studentEmail }],
                reminders: {
                    'useDefault': false,
                    'overrides': [{'method': 'email', 'minutes': 24 * 60}, {'method': 'popup', 'minutes': 30}],
                },
            };

            await calendar.events.insert({ calendarId: 'primary', resource: event });
            console.log('Google Calendar event created for faculty:', facultyEmail);
        }
    } catch (calendarError) {
        console.error('Failed to create Google Calendar event:', calendarError.message);
    }
}


app.post('/api/appointments/:id/status', authMiddleware, async (req, res) => {
    if (req.user.role !== 'faculty') {
        return res.status(403).json({ message: 'Permission denied.' });
    }
    try {
        const { status } = req.body;
        const { id } = req.params;
        const result = await pool.query(`UPDATE appointments SET status = $1 WHERE id = $2 AND faculty_id = $3 RETURNING *`, [status, id, req.user.id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Appointment not found or you do not have permission.' });
        }
        res.json({ message: `Appointment ${status}!`, appointment: result.rows[0] });
    } catch (error) {
        console.error('Error updating appointment status:', error);
        res.status(500).json({ message: 'Error updating appointment status.' });
    }
});

app.post('/api/appointments/:id/reschedule', authMiddleware, async (req, res) => {
    if (req.user.role !== 'faculty') {
        return res.status(403).json({ message: 'Permission denied.' });
    }
    
    const { date, time } = req.body;
    const { id: appointmentId } = req.params;

    if (!date || !time) return res.status(400).json({ message: 'New date and time are required.' });
    
    if (!isAppointmentTimeValid(date, time)) {
        return res.status(400).json({ message: 'Appointments can only be rescheduled to weekdays between 9:00 AM and 5:00 PM.' });
    }

    try {
        const result = await pool.query(
            `UPDATE appointments SET status = 'rescheduled', date = $1, time = $2 WHERE id = $3 AND faculty_id = $4 RETURNING id, student_id, purpose`,
            [date, time, appointmentId, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ message: 'Appointment not found or you do not have permission.' });
        
        const appointment = result.rows[0];
        const studentResult = await pool.query('SELECT name, email FROM users WHERE id = $1', [appointment.student_id]);
        
        if (studentResult.rows.length > 0) {
            const student = studentResult.rows[0];
            const mailOptions = { from: process.env.EMAIL_USER, to: student.email, subject: 'Important: Your Appointment has been Rescheduled', text: `Hello ${student.name},\n\nYour appointment with ${req.user.name} regarding "${appointment.purpose}" has been rescheduled.\n\nNew Date: ${date}\nNew Time: ${time}\n\nPlease log in to the portal to view details.\n\nThank you.`};
            await transporter.sendMail(mailOptions);
        }
        res.json({ message: 'Appointment rescheduled and student notified!', appointment });
    } catch (error) {
        console.error('Error rescheduling appointment:', error);
        res.status(500).json({ message: 'Error rescheduling appointment.' });
    }
});


// --- Serve Frontend ---
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Start Server & Graceful Shutdown ---
const server = app.listen(PORT, async () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    //await setupDatabase(); // IMPORTANT: Run this once to set up your DB, then comment it out.
});

const gracefulShutdown = () => {
    console.log('\nReceived shutdown signal. Closing server gracefully...');

    // 1. Stop the server from accepting new connections
    server.close(() => {
        console.log('Express server closed.');

        // 2. Close the database pool to end all connections
        pool.end(() => {
            console.log('Database pool has been closed.');
            process.exit(0);
        });
    });

    // Force shutdown if it takes too long
    setTimeout(() => {
        console.error('Could not close connections in time, forcefully shutting down.');
        process.exit(1);
    }, 10000); // 10-second timeout
};

// Listen for termination signals (e.g., Ctrl+C, nodemon restart)
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);