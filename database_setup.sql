-- Drop tables in reverse order of dependency to avoid errors
DROP TABLE IF EXISTS appointments;
DROP TABLE IF EXISTS faculty_profiles;
DROP TABLE IF EXISTS users;

-- Create the main users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('student', 'faculty')),
    year_semester VARCHAR(100), -- For students
    department VARCHAR(255),
    designation VARCHAR(255),   -- For faculty
    office VARCHAR(255),        -- For faculty
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create faculty-specific profiles, linked to the users table
CREATE TABLE faculty_profiles (
    user_id INT PRIMARY KEY,
    availability JSONB DEFAULT '{}'::jsonb,
    show_schedule BOOLEAN DEFAULT TRUE,
    show_location BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_user
        FOREIGN KEY(user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- Create the appointments table
CREATE TABLE appointments (
    id SERIAL PRIMARY KEY,
    student_id INT NOT NULL,
    faculty_id INT NOT NULL,
    purpose TEXT NOT NULL,
    date VARCHAR(50) NOT NULL,
    time VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'rescheduled')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_student
        FOREIGN KEY(student_id) 
        REFERENCES users(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_faculty
        FOREIGN KEY(faculty_id) 
        REFERENCES users(id)
        ON DELETE CASCADE
);

-- Add indexes for faster lookups
CREATE INDEX idx_appointments_student_id ON appointments(student_id);
CREATE INDEX idx_appointments_faculty_id ON appointments(faculty_id);

-- Insert a test faculty user. Password is 'password'
INSERT INTO users (name, email, password, role, department, designation, office)
VALUES ('Dr. Muzafar Rasool', 'm.rasool@i.com', '$2a$10$JfVsXSRtIAxSnYoVAZXBcuw4W33Uj1fz0zUT9GWKNSEP6bcxhl90a', 'faculty', 'Computer Science', 'Professor', 'Block IV - S01');
INSERT INTO faculty_profiles (user_id) VALUES ( (SELECT id FROM users WHERE email = 'm.rasool@i.com') );

-- Insert a test student user. Password is 'password'
INSERT INTO users (name, email, password, role, department, year_semester)
VALUES ('Syed Afaan', 'afaan@s.com', '$2a$10$q/MAaYf6xIiW4tVNgENSb.pTdkwOWiQNSfoD448UuQbfWodj6oLjS', 'student', 'Computer Science', '3rd Year');