CREATE DATABASE IF NOT EXISTS `cyberhud_db`;
USE `cyberhud_db`;

CREATE TABLE IF NOT EXISTS `users` (
  `id` varchar(50) NOT NULL,
  `username` varchar(50) DEFAULT NULL,
  `hashed_password` varchar(255) DEFAULT NULL,
  `roles` json DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_users_username` (`username`),
  KEY `ix_users_id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT IGNORE INTO `users` (`id`, `username`, `hashed_password`, `roles`, `is_active`) 
VALUES ('1', 'admin', SHA2('admin', 256), '["admin", "user"]', 1);
