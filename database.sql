CREATE DATABASE IF NOT EXISTS ams;
USE ams;

CREATE TABLE IF NOT EXISTS admin (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  username   VARCHAR(50)  NOT NULL UNIQUE,
  password   TEXT         NOT NULL,
  email      VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS courses (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  course_id   VARCHAR(20)  NOT NULL UNIQUE,
  course_name VARCHAR(100) NOT NULL,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO courses (course_id, course_name)
VALUES ('UNKNOWN', 'Unknown / Legacy');

CREATE TABLE IF NOT EXISTS faculty (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(100) NOT NULL,
  username   VARCHAR(50)  NOT NULL UNIQUE,
  password   TEXT         NOT NULL,
  email      VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS students (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  roll       VARCHAR(20)  NOT NULL UNIQUE,
  name       VARCHAR(100) NOT NULL,
  email      VARCHAR(100),
  password   TEXT         NOT NULL,
  face_image VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attendance (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  roll       VARCHAR(20)  NOT NULL,
  course_id  VARCHAR(20)  NOT NULL DEFAULT 'UNKNOWN',
  date       DATE         NOT NULL,
  status     ENUM('Present','Absent','Late') DEFAULT 'Present',
  device_fp  VARCHAR(16)  DEFAULT NULL,
  latitude   DOUBLE       DEFAULT NULL,
  longitude  DOUBLE       DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (roll)      REFERENCES students(roll),
  FOREIGN KEY (course_id) REFERENCES courses(course_id)
);

INSERT IGNORE INTO admin (username, password, email)
VALUES (
  'admin',
  'pbkdf2:sha256:260000$rLDiCjBYp2wqrMlU$e7f8d2b9c1a4e6f8d2b9c1a4e6f8d2b9c1a4e6f8d2b9c1a4e6f8d2b9c1a4e6f8',
  'admin@ams.local'
);
-- ── Courses table ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS courses (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  course_id   VARCHAR(20)  NOT NULL UNIQUE,
  course_name VARCHAR(100) NOT NULL,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Ensure fallback course for legacy rows
INSERT IGNORE INTO courses (course_id, course_name)
VALUES ('UNKNOWN', 'Unknown / Legacy');

-- ── Faculty table ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS faculty (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(100) NOT NULL,
  username   VARCHAR(50)  NOT NULL UNIQUE,
  password   TEXT         NOT NULL,          -- TEXT: fits any werkzeug hash
  email      VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Students table ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS students (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  roll       VARCHAR(20)  NOT NULL UNIQUE,
  name       VARCHAR(100) NOT NULL,
  email      VARCHAR(100),
  password   TEXT         NOT NULL,          -- TEXT: fits any werkzeug hash
  face_image VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Attendance table ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS attendance (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  roll       VARCHAR(20)  NOT NULL,
  course_id  VARCHAR(20)  NOT NULL DEFAULT 'UNKNOWN',
  date       DATE         NOT NULL,
  status     ENUM('Present','Absent','Late') DEFAULT 'Present',
  device_fp  VARCHAR(16)  DEFAULT NULL,
  latitude   DOUBLE       DEFAULT NULL,
  longitude  DOUBLE       DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (roll)      REFERENCES students(roll),
  FOREIGN KEY (course_id) REFERENCES courses(course_id)
);

-- ── Incremental migrations (safe on existing DB) ──────────
-- Widen password columns if they are still VARCHAR
ALTER TABLE admin     MODIFY COLUMN password TEXT NOT NULL;
ALTER TABLE faculty   MODIFY COLUMN password TEXT NOT NULL;
ALTER TABLE students  MODIFY COLUMN password TEXT NOT NULL;

-- Add email to admin if missing
ALTER TABLE admin ADD COLUMN IF NOT EXISTS email VARCHAR(100) AFTER password;

-- Add course_id to attendance if missing
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS
  course_id VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN' AFTER roll;

-- Add anti-proxy columns
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS device_fp VARCHAR(16) DEFAULT NULL;
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS latitude DOUBLE DEFAULT NULL;
ALTER TABLE attendance ADD COLUMN IF NOT EXISTS longitude DOUBLE DEFAULT NULL;

-- ── Default admin account ─────────────────────────────────
-- Password: admin123   (pbkdf2:sha256 hash — matches app.py make_password_hash)
-- To change: python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('yourpass', method='pbkdf2:sha256'))"
INSERT IGNORE INTO admin (username, password, email)
VALUES (
  'admin',
  'pbkdf2:sha256:260000$rLDiCjBYp2wqrMlU$e7f8d2b9c1a4e6f8d2b9c1a4e6f8d2b9c1a4e6f8d2b9c1a4e6f8d2b9c1a4e6f8',
  'admin@ams.local'
);
