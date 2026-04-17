-- =============================================
-- database.sql — Folio v2
-- Run this in phpMyAdmin SQL tab
-- =============================================

CREATE DATABASE IF NOT EXISTS auth_system;
USE auth_system;

-- =============================================
-- users — core account info
-- =============================================
CREATE TABLE IF NOT EXISTS users (
    id           INT          NOT NULL AUTO_INCREMENT,
    first_name   VARCHAR(50)  NOT NULL,
    last_name    VARCHAR(50)  NOT NULL,
    email        VARCHAR(100) NOT NULL UNIQUE,
    password     VARCHAR(255) NOT NULL,
    username     VARCHAR(50)  DEFAULT '',
    tagline      VARCHAR(200) DEFAULT '',
    bio          TEXT         DEFAULT '',
    gender       VARCHAR(20)  DEFAULT '',
    phone        VARCHAR(30)  DEFAULT '',
    address      TEXT         DEFAULT '',
    location     VARCHAR(100) DEFAULT '',
    website      VARCHAR(200) DEFAULT '',
    github       VARCHAR(200) DEFAULT '',
    linkedin     VARCHAR(200) DEFAULT '',
    twitter      VARCHAR(200) DEFAULT '',
    avatar_path  VARCHAR(300) DEFAULT '',
    twofa_enabled TINYINT(1)  DEFAULT 1,
    project_count INT         DEFAULT 0,
    profile_views INT         DEFAULT 0,
    created_at   DATETIME     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

-- =============================================
-- login_attempts — brute force protection
-- =============================================
CREATE TABLE IF NOT EXISTS login_attempts (
    id           INT          NOT NULL AUTO_INCREMENT,
    email        VARCHAR(100) NOT NULL,
    attempt_time DATETIME     DEFAULT CURRENT_TIMESTAMP,
    ip_address   VARCHAR(45)  DEFAULT '',
    PRIMARY KEY (id)
);

-- =============================================
-- otp_tokens — 2FA codes
-- =============================================
CREATE TABLE IF NOT EXISTS otp_tokens (
    id         INT          NOT NULL AUTO_INCREMENT,
    user_id    INT          NOT NULL,
    otp_code   VARCHAR(255) NOT NULL,
    expires_at DATETIME     NOT NULL,
    used       TINYINT(1)   DEFAULT 0,
    created_at DATETIME     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- =============================================
-- experience — work history
-- =============================================
CREATE TABLE IF NOT EXISTS experience (
    id          INT          NOT NULL AUTO_INCREMENT,
    user_id     INT          NOT NULL,
    company     VARCHAR(100) NOT NULL,
    position    VARCHAR(100) NOT NULL,
    date_start  VARCHAR(20)  DEFAULT '',
    date_end    VARCHAR(20)  DEFAULT '',  -- empty = "Present"
    description TEXT         DEFAULT '',
    sort_order  INT          DEFAULT 0,
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- =============================================
-- education — academic history
-- =============================================
CREATE TABLE IF NOT EXISTS education (
    id          INT          NOT NULL AUTO_INCREMENT,
    user_id     INT          NOT NULL,
    institution VARCHAR(100) NOT NULL,
    degree      VARCHAR(100) NOT NULL,
    field       VARCHAR(100) DEFAULT '',
    year_start  VARCHAR(10)  DEFAULT '',
    year_end    VARCHAR(10)  DEFAULT '',
    description TEXT         DEFAULT '',
    sort_order  INT          DEFAULT 0,
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- =============================================
-- skills
-- =============================================
CREATE TABLE IF NOT EXISTS skills (
    id          INT         NOT NULL AUTO_INCREMENT,
    user_id     INT         NOT NULL,
    name        VARCHAR(80) NOT NULL,
    category    VARCHAR(80) DEFAULT 'General',
    proficiency ENUM('beginner','intermediate','advanced','expert') DEFAULT 'intermediate',
    sort_order  INT         DEFAULT 0,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- =============================================
-- projects
-- =============================================
CREATE TABLE IF NOT EXISTS projects (
    id          INT          NOT NULL AUTO_INCREMENT,
    user_id     INT          NOT NULL,
    title       VARCHAR(100) NOT NULL,
    description TEXT         DEFAULT '',
    tech_stack  VARCHAR(300) DEFAULT '',  -- comma-separated: "PHP,MySQL,CSS"
    github_url  VARCHAR(300) DEFAULT '',
    live_url    VARCHAR(300) DEFAULT '',
    sort_order  INT          DEFAULT 0,
    created_at  DATETIME     DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
