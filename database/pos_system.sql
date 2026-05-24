-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 24, 2026 at 05:14 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `pos_system`
--

-- --------------------------------------------------------

--
-- Table structure for table `admins`
--

CREATE TABLE `admins` (
  `admin_id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL DEFAULT '',
  `password` varchar(255) NOT NULL DEFAULT '',
  `full_name` varchar(255) NOT NULL DEFAULT '',
  `username_hash` varchar(64) DEFAULT NULL,
  `password_hash` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admins`
--

INSERT INTO `admins` (`admin_id`, `username`, `password`, `full_name`, `username_hash`, `password_hash`) VALUES
(2, 'pOrHJlyooxdx3CVqHvSRgyWDVQQ3bvfISEj6f8X9AKpj+5HoRSdkhhb4E8eO4Fc1GHjRK81YDeYLdTmQ51Eaqg==', '+CMjiy/KORMlAkgkGzKEexqnhqKwHNPMyfPYJ7uWEydKQG09hKKoj+dg1q0X6s52YA7SVW8zdwLmzWoLw6YLzA==', 'PUyTZmrdNPGt68dv0xUsJUw7QMryuQuVJ3H8WiPlGZDRCdxoPeR9Xz6qwEp8U0uK9uSE9A/tI5NLaUwp+fbTIg==', '7468a23c0f79ffb77972d5e29a97b70c2a0e0d334d371cb0e4001d9e7db4b84b', '$2b$12$J19GG.l5tS/IjltwbTHIuO1pXQAFJFr0FPhkMCAPaPDcBDUvJJvIq'),
(3, '1HHYjdz/S79d9eZr9LLJ4oeU/HO3L+x6KPdPHmtGKM0=', 'rOIvmrdJupy0dG828w/HyzOjCWu/JF5RCe4xg2vnJo8=', '7FUDZ+z6RzpeRZ2F1u1/NAntWnD3NergD4zCAa7hHc0=', '715004213ff39151819aea6a5256a3c89d4d4f88ca1077f4081fae623be06b1b', '$2b$12$diK/bft0r5ts5ScZ5KmF2OnF5gg15MNRYuAwIwegX6edWoLbXx7l2');

-- --------------------------------------------------------

--
-- Table structure for table `app_settings`
--

CREATE TABLE `app_settings` (
  `setting_key` varchar(100) NOT NULL,
  `setting_value` varchar(500) NOT NULL DEFAULT '',
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `app_settings`
--

INSERT INTO `app_settings` (`setting_key`, `setting_value`, `updated_at`) VALUES
('late_grace_minutes', '10', '2026-05-19 13:49:20'),
('late_per_minute_rate', '0.7500', '2026-05-24 04:55:32');

-- --------------------------------------------------------

--
-- Table structure for table `attendance`
--

CREATE TABLE `attendance` (
  `attendance_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `shift_type` varchar(50) DEFAULT NULL,
  `clock_in` datetime DEFAULT NULL,
  `clock_out` datetime DEFAULT NULL,
  `attendance_date` date NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `hours_worked` decimal(10,4) NOT NULL DEFAULT 0.0000,
  `hourly_rate_snapshot` decimal(10,2) NOT NULL DEFAULT 0.00,
  `daily_earnings` decimal(10,2) NOT NULL DEFAULT 0.00,
  `pay_period_start` date DEFAULT NULL,
  `pay_period_end` date DEFAULT NULL,
  `daily_pay` decimal(10,2) DEFAULT NULL,
  `late_minutes` int(11) NOT NULL DEFAULT 0,
  `late_deduction` decimal(10,2) NOT NULL DEFAULT 0.00,
  `deduction_waived` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `categories`
--

CREATE TABLE `categories` (
  `category_id` int(10) UNSIGNED NOT NULL,
  `name` varchar(80) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `categories`
--

INSERT INTO `categories` (`category_id`, `name`, `created_at`) VALUES
(35, 'MILKTEA', '2026-04-05 16:23:19'),
(36, 'SNAKS', '2026-05-19 14:06:02');

-- --------------------------------------------------------

--
-- Table structure for table `email_alert_settings`
--

CREATE TABLE `email_alert_settings` (
  `id` int(11) NOT NULL,
  `smtp_host` varchar(255) NOT NULL DEFAULT '',
  `smtp_port` smallint(6) NOT NULL DEFAULT 587,
  `smtp_user` varchar(255) NOT NULL DEFAULT '',
  `smtp_password` varchar(255) NOT NULL DEFAULT '',
  `smtp_use_tls` tinyint(1) NOT NULL DEFAULT 1,
  `alert_recipient` varchar(255) NOT NULL DEFAULT '',
  `low_stock_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `low_stock_threshold` int(11) NOT NULL DEFAULT 5,
  `daily_summary_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `new_employee_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `failed_login_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `maintenance_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `email_alert_settings`
--

INSERT INTO `email_alert_settings` (`id`, `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_use_tls`, `alert_recipient`, `low_stock_enabled`, `low_stock_threshold`, `daily_summary_enabled`, `new_employee_enabled`, `failed_login_enabled`, `maintenance_enabled`, `updated_at`) VALUES
(1, 'smtp.gmail.com', 587, 'patrimoniodrexler1@gmail.com', 'btvr qvkl xdpd wrtd', 1, 'patrimoniodrexler1@gmail.com', 1, 0, 1, 0, 1, 0, '2026-04-10 14:46:50');

-- --------------------------------------------------------

--
-- Table structure for table `employees`
--

CREATE TABLE `employees` (
  `employee_id` int(11) NOT NULL,
  `application_id` int(11) DEFAULT NULL,
  `full_name` varchar(255) NOT NULL DEFAULT '',
  `username` varchar(255) NOT NULL DEFAULT '',
  `password` varchar(255) NOT NULL DEFAULT '',
  `role` enum('admin','manager','cashier') NOT NULL DEFAULT 'cashier',
  `contact_number` varchar(255) NOT NULL DEFAULT '',
  `employment_status` enum('active','inactive','terminated') DEFAULT 'active',
  `face_image_path` varchar(255) DEFAULT NULL,
  `face_model_path` mediumtext DEFAULT NULL,
  `last_login` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `disabled_at` datetime DEFAULT NULL,
  `username_hash` varchar(64) DEFAULT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `hourly_rate` decimal(10,2) NOT NULL DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `employees_trash`
--

CREATE TABLE `employees_trash` (
  `trash_id` int(10) UNSIGNED NOT NULL,
  `employee_id` int(11) NOT NULL,
  `full_name` varchar(255) NOT NULL DEFAULT '',
  `username` varchar(255) NOT NULL DEFAULT '',
  `username_hash` varchar(64) DEFAULT NULL,
  `password` varchar(255) NOT NULL DEFAULT '',
  `password_hash` varchar(255) DEFAULT NULL,
  `role` enum('admin','manager','cashier') NOT NULL DEFAULT 'cashier',
  `contact_number` varchar(255) NOT NULL DEFAULT '',
  `face_image_path` varchar(255) DEFAULT NULL,
  `face_model_path` mediumtext DEFAULT NULL,
  `last_login` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `disabled_at` datetime NOT NULL DEFAULT current_timestamp(),
  `delete_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `employee_applications`
--

CREATE TABLE `employee_applications` (
  `application_id` int(11) NOT NULL,
  `full_name` varchar(255) NOT NULL DEFAULT '',
  `email` varchar(255) NOT NULL DEFAULT '',
  `username` varchar(255) NOT NULL DEFAULT '',
  `role` enum('admin','manager','cashier') NOT NULL DEFAULT 'cashier',
  `contact_number` varchar(255) NOT NULL DEFAULT '',
  `status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `face_mismatch_log`
--

CREATE TABLE `face_mismatch_log` (
  `id` int(10) UNSIGNED NOT NULL,
  `employee_id` int(11) NOT NULL,
  `attempted_at` datetime NOT NULL DEFAULT current_timestamp(),
  `distance_score` float DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `face_mismatch_log`
--

INSERT INTO `face_mismatch_log` (`id`, `employee_id`, `attempted_at`, `distance_score`, `ip_address`, `user_agent`) VALUES
(1, 1, '2026-03-25 08:55:09', 0.6711, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(2, 1, '2026-03-25 08:55:32', 0.6885, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(3, 1, '2026-03-25 08:55:45', 0.7331, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(4, 1, '2026-03-25 12:33:22', 0.3156, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(5, 1, '2026-03-25 12:33:28', 0.8002, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(6, 1, '2026-03-25 12:33:43', 0.4578, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(7, 1, '2026-03-25 12:33:53', 0.4503, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(8, 1, '2026-03-25 12:33:58', 0.301, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(9, 1, '2026-03-25 12:34:04', 0.3761, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(10, 1, '2026-03-25 12:35:08', 0.4677, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(11, 2, '2026-03-25 12:36:56', 0.3106, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(12, 2, '2026-03-25 12:37:13', 0.367, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(13, 2, '2026-03-25 12:38:00', 0.4079, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(14, 2, '2026-03-25 12:38:14', 0.6877, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(15, 2, '2026-03-25 12:39:01', 0.3209, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(16, 2, '2026-03-25 12:39:20', 0.3051, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(17, 2, '2026-03-25 12:39:39', 0.7074, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(18, 2, '2026-03-25 12:42:29', 0.6511, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(19, 2, '2026-03-25 12:42:33', 0.6217, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(20, 2, '2026-03-25 12:42:35', 0.6179, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(21, 2, '2026-03-25 13:23:52', 0.6914, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(22, 2, '2026-03-25 13:24:06', 0.6406, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(23, 2, '2026-03-25 14:28:32', 0.662, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(24, 2, '2026-03-25 14:30:42', 0.6833, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(25, 2, '2026-03-25 15:00:52', 0.4435, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(26, 3, '2026-03-25 15:00:56', 0.5634, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(27, 3, '2026-03-25 15:01:08', 0.4741, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(28, 2, '2026-03-25 15:01:09', 0.4562, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(29, 3, '2026-03-25 15:01:19', 0.4432, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(30, 2, '2026-03-25 15:01:32', 0.4416, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(31, 3, '2026-03-25 15:19:36', 0.5779, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(32, 3, '2026-03-25 15:48:58', 0.6949, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(33, 3, '2026-03-25 16:27:39', 0.517, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(34, 5, '2026-03-26 07:41:25', 0.3381, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(35, 5, '2026-03-26 07:41:42', 0.6013, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(36, 5, '2026-03-26 07:45:05', 0.4796, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(37, 5, '2026-03-26 07:46:25', 0.8069, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(38, 3, '2026-03-27 00:14:49', 0.5249, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(39, 3, '2026-03-27 00:29:10', 0.5543, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(40, 3, '2026-03-27 00:29:46', 0.58, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(41, 3, '2026-03-27 00:30:47', 0.6344, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(42, 5, '2026-03-27 07:54:34', 0.5163, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(43, 3, '2026-03-31 23:38:48', 0.5825, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0');

-- --------------------------------------------------------

--
-- Table structure for table `inv_items`
--

CREATE TABLE `inv_items` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(120) NOT NULL,
  `type` enum('ingredient','packaging') NOT NULL DEFAULT 'ingredient',
  `stock` decimal(12,2) NOT NULL DEFAULT 0.00,
  `unit` varchar(20) NOT NULL DEFAULT 'pcs',
  `reorder_point` decimal(12,2) NOT NULL DEFAULT 10.00,
  `note` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `inv_items`
--

INSERT INTO `inv_items` (`id`, `name`, `type`, `stock`, `unit`, `reorder_point`, `note`, `is_active`, `created_at`, `updated_at`) VALUES
(4, '8oz Cup', 'packaging', 21.00, '8oz', 20.00, 'Cup packaging — auto-deducted on sales', 1, '2026-04-05 16:03:13', '2026-04-10 15:01:36'),
(5, '12oz Cup', 'packaging', 5.00, '12oz', 20.00, 'Cup packaging — auto-deducted on sales', 0, '2026-04-05 16:03:21', '2026-05-24 08:00:27'),
(6, '16oz Cup', 'packaging', 5.00, '16oz', 20.00, 'Cup packaging — auto-deducted on sales', 0, '2026-04-05 16:03:28', '2026-05-24 08:00:30'),
(7, 'Sugar', 'ingredient', 2.00, 'kg', 10.00, NULL, 1, '2026-04-10 15:02:25', '2026-04-10 15:18:50'),
(8, 'Brown Syrup', 'packaging', 1.00, 'bottle', 10.00, NULL, 1, '2026-04-24 14:47:59', '2026-04-24 14:47:59'),
(11, 'Water', 'packaging', 1.00, 'ml', 10.00, NULL, 0, '2026-05-24 06:27:38', '2026-05-24 06:27:47'),
(12, '20z cup', 'packaging', 1.00, '20oz', 20.00, 'Cup packaging — auto-deducted on sales', 0, '2026-05-24 06:54:42', '2026-05-24 07:43:44'),
(13, '26 cup', 'packaging', 1.00, '26oz', 20.00, 'Cup packaging — auto-deducted on sales', 0, '2026-05-24 07:29:02', '2026-05-24 07:43:51'),
(14, '1', 'packaging', 0.00, '1oz', 20.00, 'Cup packaging — auto-deducted on sales', 0, '2026-05-24 07:29:20', '2026-05-24 07:43:04'),
(15, '2', 'packaging', 2.00, '2oz', 20.00, 'Cup packaging — auto-deducted on sales', 0, '2026-05-24 07:42:55', '2026-05-24 07:43:08'),
(16, '1', 'packaging', 1.00, '1oz', 20.00, 'Cup packaging — auto-deducted on sales', 1, '2026-05-24 07:57:18', '2026-05-24 07:57:18'),
(17, '2oz Cup', 'packaging', 2.00, '2oz', 20.00, 'Cup packaging — auto-deducted on sales', 1, '2026-05-24 07:57:33', '2026-05-24 07:57:33');

-- --------------------------------------------------------

--
-- Table structure for table `inv_log`
--

CREATE TABLE `inv_log` (
  `log_id` int(10) UNSIGNED NOT NULL,
  `item_id` int(10) UNSIGNED NOT NULL,
  `item_name` varchar(120) NOT NULL DEFAULT '',
  `unit` varchar(20) NOT NULL DEFAULT 'pcs',
  `delta` decimal(12,2) NOT NULL,
  `stock_after` decimal(12,2) NOT NULL,
  `source` enum('sale','manual') NOT NULL DEFAULT 'manual',
  `transaction_id` int(10) UNSIGNED DEFAULT NULL,
  `note` varchar(255) DEFAULT NULL,
  `created_by` varchar(80) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `inv_log`
--

INSERT INTO `inv_log` (`log_id`, `item_id`, `item_name`, `unit`, `delta`, `stock_after`, `source`, `transaction_id`, `note`, `created_by`, `created_at`) VALUES
(11, 4, '8oz Cup', '8oz', 1.00, 6.00, 'manual', NULL, NULL, 'Drexler', '2026-04-05 16:23:06'),
(12, 4, '8oz Cup', '8oz', -1.00, 5.00, 'sale', 18, 'Auto-deducted via TXN #18', 'Patrimonio', '2026-04-05 17:03:27'),
(13, 4, '8oz Cup', '8oz', -1.00, 4.00, 'sale', 19, 'Auto-deducted via TXN #19', 'Patrimonio', '2026-04-05 17:07:59'),
(14, 4, '8oz Cup', '8oz', -1.00, 3.00, 'sale', 20, 'Auto-deducted via TXN #20', 'Patrimonio', '2026-04-05 17:13:34'),
(15, 4, '8oz Cup', '8oz', -1.00, 2.00, 'sale', 21, 'Auto-deducted via TXN #21', 'Patrimonio', '2026-04-09 13:18:26'),
(16, 4, '8oz Cup', '8oz', -1.00, 1.00, 'sale', 22, 'Auto-deducted via TXN #22', 'Patrimonio', '2026-04-10 13:32:09'),
(17, 4, '8oz Cup', '8oz', 5.00, 6.00, 'manual', NULL, NULL, 'Drexler', '2026-04-10 15:01:24'),
(18, 4, '8oz Cup', '8oz', 5.00, 11.00, 'manual', NULL, NULL, 'Drexler', '2026-04-10 15:01:29'),
(19, 4, '8oz Cup', '8oz', 10.00, 21.00, 'manual', NULL, NULL, 'Drexler', '2026-04-10 15:01:36'),
(20, 7, 'Sugar', 'kg', 1.00, 2.00, 'manual', NULL, NULL, 'Drexler', '2026-04-10 15:18:50'),
(21, 14, '1', '1oz', -10.00, 0.00, 'manual', NULL, NULL, 'Drexler', '2026-05-24 07:42:39'),
(22, 14, '1', '1oz', -10.00, 0.00, 'manual', NULL, NULL, 'Drexler', '2026-05-24 07:42:41');

-- --------------------------------------------------------

--
-- Table structure for table `login_attempts`
--

CREATE TABLE `login_attempts` (
  `attempt_key` varchar(64) NOT NULL,
  `fail_count` int(11) NOT NULL DEFAULT 0,
  `locked_until` datetime DEFAULT NULL,
  `last_attempt` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `login_attempts`
--

INSERT INTO `login_attempts` (`attempt_key`, `fail_count`, `locked_until`, `last_attempt`) VALUES
('0f50b0d848d29f2476624f171dc2d442266e35bed28ad11e830d6cf09f2b0929', 3, NULL, '2026-04-04 14:34:07'),
('3049ea9e4b0a7b1b19db0afff84bc4434878d00c503dc9b9fa6a8a257c4f67e6', 4, NULL, '2026-03-26 11:36:53'),
('85d636564759f084aae5de99f84bf6246f97cfea6c02769f55484c7eba9bec4d', 5, '2026-04-05 17:42:20', '2026-04-05 17:27:20'),
('a49a0bc44eb86fb946e61a404978255950b48af6daaaec520e2a6fdd8120104c', 1, NULL, '2026-04-24 15:00:51'),
('e25ad1324256a7a6b85f2aaa40471b668eb807c2334bcefeffde0ee1e40ebf46', 4, NULL, '2026-05-24 08:01:19');

-- --------------------------------------------------------

--
-- Table structure for table `overtime_requests`
--

CREATE TABLE `overtime_requests` (
  `request_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `attendance_id` int(11) DEFAULT NULL,
  `request_date` date NOT NULL,
  `extended_hours` decimal(4,2) NOT NULL,
  `reason` varchar(500) NOT NULL DEFAULT '',
  `status` enum('pending','approved','denied','cancelled') NOT NULL DEFAULT 'pending',
  `reviewed_by` varchar(255) DEFAULT NULL,
  `reviewed_at` datetime DEFAULT NULL,
  `admin_note` varchar(500) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `payroll_periods`
--

CREATE TABLE `payroll_periods` (
  `payroll_id` int(10) UNSIGNED NOT NULL,
  `employee_id` int(11) NOT NULL,
  `period_start` date NOT NULL,
  `period_end` date NOT NULL,
  `total_hours` decimal(8,2) NOT NULL DEFAULT 0.00,
  `total_pay` decimal(12,2) NOT NULL DEFAULT 0.00,
  `days_worked` smallint(6) NOT NULL DEFAULT 0,
  `status` enum('draft','finalized') NOT NULL DEFAULT 'draft',
  `generated_at` datetime NOT NULL DEFAULT current_timestamp(),
  `finalized_at` datetime DEFAULT NULL,
  `notes` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `products`
--

CREATE TABLE `products` (
  `product_id` int(10) UNSIGNED NOT NULL,
  `category_id` int(10) UNSIGNED DEFAULT NULL,
  `name` varchar(120) NOT NULL,
  `description` text DEFAULT NULL,
  `sku` varchar(60) DEFAULT NULL,
  `price` decimal(10,2) NOT NULL DEFAULT 0.00,
  `cost` decimal(10,2) NOT NULL DEFAULT 0.00,
  `stock` int(11) NOT NULL DEFAULT 0,
  `reorder_point` int(11) NOT NULL DEFAULT 5,
  `unit` varchar(30) NOT NULL DEFAULT 'pcs',
  `icon` varchar(10) NOT NULL DEFAULT '?',
  `image_url` varchar(512) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `cup_eligible` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `products`
--

INSERT INTO `products` (`product_id`, `category_id`, `name`, `description`, `sku`, `price`, `cost`, `stock`, `reorder_point`, `unit`, `icon`, `image_url`, `is_active`, `created_at`, `updated_at`, `cup_eligible`) VALUES
(31, 35, 'Spanish Latte', NULL, 'MT-001', 140.00, 50.00, -7, 5, 'pcs', '📦', '/static/product_images/prod_d9f2c031002e661d58c969ff.jpg', 1, '2026-04-05 16:23:44', '2026-04-13 13:16:38', 1),
(32, 36, 'Cheepy', NULL, NULL, 30.00, 10.00, 0, 5, 'pcs', '?', NULL, 1, '2026-05-19 14:06:24', '2026-05-19 14:06:24', 0);

-- --------------------------------------------------------

--
-- Table structure for table `shift_config`
--

CREATE TABLE `shift_config` (
  `id` int(11) NOT NULL,
  `label` varchar(100) NOT NULL,
  `start_time` varchar(5) NOT NULL,
  `end_time` varchar(5) NOT NULL,
  `color` varchar(20) NOT NULL DEFAULT '#c9a961',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `shift_config`
--

INSERT INTO `shift_config` (`id`, `label`, `start_time`, `end_time`, `color`, `created_at`) VALUES
(1, '8AM', '08:00', '18:00', '#4caf50', '2026-05-19 14:12:12');

-- --------------------------------------------------------

--
-- Table structure for table `stock_requests`
--

CREATE TABLE `stock_requests` (
  `id` int(10) UNSIGNED NOT NULL,
  `item_name` varchar(120) NOT NULL,
  `item_type` enum('ingredient','packaging') NOT NULL DEFAULT 'ingredient',
  `quantity` decimal(12,2) NOT NULL DEFAULT 0.00,
  `unit` varchar(20) NOT NULL DEFAULT 'pcs',
  `note` varchar(255) DEFAULT NULL,
  `requested_by` varchar(80) NOT NULL,
  `requested_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  `reviewed_by` varchar(80) DEFAULT NULL,
  `reviewed_at` timestamp NULL DEFAULT NULL,
  `review_note` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `transactions`
--

CREATE TABLE `transactions` (
  `transaction_id` int(10) UNSIGNED NOT NULL,
  `cashier_id` int(11) NOT NULL,
  `cashier_name` varchar(255) NOT NULL DEFAULT '',
  `subtotal` decimal(12,2) NOT NULL DEFAULT 0.00,
  `discount_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `tax_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `total_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `amount_tendered` decimal(12,2) NOT NULL DEFAULT 0.00,
  `change_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `payment_method` enum('cash','card','gcash','maya','other') NOT NULL DEFAULT 'cash',
  `note` varchar(255) DEFAULT NULL,
  `status` enum('completed','voided') NOT NULL DEFAULT 'completed',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `discount_type` enum('none','senior','pwd','manual') NOT NULL DEFAULT 'none',
  `net_sales` decimal(12,2) NOT NULL DEFAULT 0.00,
  `vat_amount` decimal(12,2) NOT NULL DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `transaction_items`
--

CREATE TABLE `transaction_items` (
  `item_id` int(10) UNSIGNED NOT NULL,
  `transaction_id` int(10) UNSIGNED NOT NULL,
  `product_id` int(10) UNSIGNED DEFAULT NULL,
  `product_name` varchar(120) NOT NULL,
  `category_name` varchar(80) NOT NULL DEFAULT '',
  `unit_price` decimal(10,2) NOT NULL DEFAULT 0.00,
  `quantity` int(11) NOT NULL DEFAULT 1,
  `line_total` decimal(12,2) NOT NULL DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admins`
--
ALTER TABLE `admins`
  ADD PRIMARY KEY (`admin_id`);

--
-- Indexes for table `app_settings`
--
ALTER TABLE `app_settings`
  ADD PRIMARY KEY (`setting_key`);

--
-- Indexes for table `attendance`
--
ALTER TABLE `attendance`
  ADD PRIMARY KEY (`attendance_id`),
  ADD KEY `attendance_ibfk_1` (`employee_id`);

--
-- Indexes for table `categories`
--
ALTER TABLE `categories`
  ADD PRIMARY KEY (`category_id`),
  ADD UNIQUE KEY `uq_category_name` (`name`);

--
-- Indexes for table `email_alert_settings`
--
ALTER TABLE `email_alert_settings`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `employees`
--
ALTER TABLE `employees`
  ADD PRIMARY KEY (`employee_id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD KEY `application_id` (`application_id`);

--
-- Indexes for table `employees_trash`
--
ALTER TABLE `employees_trash`
  ADD PRIMARY KEY (`trash_id`),
  ADD KEY `idx_delete_at` (`delete_at`),
  ADD KEY `idx_employee_id` (`employee_id`);

--
-- Indexes for table `employee_applications`
--
ALTER TABLE `employee_applications`
  ADD PRIMARY KEY (`application_id`),
  ADD UNIQUE KEY `email` (`email`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `face_mismatch_log`
--
ALTER TABLE `face_mismatch_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_employee_id` (`employee_id`),
  ADD KEY `idx_attempted_at` (`attempted_at`);

--
-- Indexes for table `inv_items`
--
ALTER TABLE `inv_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_type` (`type`),
  ADD KEY `idx_active` (`is_active`);

--
-- Indexes for table `inv_log`
--
ALTER TABLE `inv_log`
  ADD PRIMARY KEY (`log_id`),
  ADD KEY `idx_item` (`item_id`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_source` (`source`);

--
-- Indexes for table `login_attempts`
--
ALTER TABLE `login_attempts`
  ADD PRIMARY KEY (`attempt_key`);

--
-- Indexes for table `overtime_requests`
--
ALTER TABLE `overtime_requests`
  ADD PRIMARY KEY (`request_id`),
  ADD KEY `idx_ot_employee` (`employee_id`),
  ADD KEY `idx_ot_status` (`status`),
  ADD KEY `idx_ot_date` (`request_date`);

--
-- Indexes for table `payroll_periods`
--
ALTER TABLE `payroll_periods`
  ADD PRIMARY KEY (`payroll_id`),
  ADD UNIQUE KEY `uq_emp_period` (`employee_id`,`period_start`),
  ADD KEY `idx_period_start` (`period_start`),
  ADD KEY `idx_employee_id` (`employee_id`);

--
-- Indexes for table `products`
--
ALTER TABLE `products`
  ADD PRIMARY KEY (`product_id`),
  ADD KEY `idx_category` (`category_id`),
  ADD KEY `idx_active` (`is_active`);

--
-- Indexes for table `shift_config`
--
ALTER TABLE `shift_config`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `stock_requests`
--
ALTER TABLE `stock_requests`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `transactions`
--
ALTER TABLE `transactions`
  ADD PRIMARY KEY (`transaction_id`),
  ADD KEY `idx_cashier` (`cashier_id`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_status` (`status`);

--
-- Indexes for table `transaction_items`
--
ALTER TABLE `transaction_items`
  ADD PRIMARY KEY (`item_id`),
  ADD KEY `idx_tx` (`transaction_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admins`
--
ALTER TABLE `admins`
  MODIFY `admin_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `attendance`
--
ALTER TABLE `attendance`
  MODIFY `attendance_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `categories`
--
ALTER TABLE `categories`
  MODIFY `category_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=37;

--
-- AUTO_INCREMENT for table `email_alert_settings`
--
ALTER TABLE `email_alert_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `employees`
--
ALTER TABLE `employees`
  MODIFY `employee_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `employees_trash`
--
ALTER TABLE `employees_trash`
  MODIFY `trash_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `employee_applications`
--
ALTER TABLE `employee_applications`
  MODIFY `application_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `face_mismatch_log`
--
ALTER TABLE `face_mismatch_log`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=44;

--
-- AUTO_INCREMENT for table `inv_items`
--
ALTER TABLE `inv_items`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT for table `inv_log`
--
ALTER TABLE `inv_log`
  MODIFY `log_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=23;

--
-- AUTO_INCREMENT for table `overtime_requests`
--
ALTER TABLE `overtime_requests`
  MODIFY `request_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `payroll_periods`
--
ALTER TABLE `payroll_periods`
  MODIFY `payroll_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `products`
--
ALTER TABLE `products`
  MODIFY `product_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=33;

--
-- AUTO_INCREMENT for table `shift_config`
--
ALTER TABLE `shift_config`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `stock_requests`
--
ALTER TABLE `stock_requests`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `transactions`
--
ALTER TABLE `transactions`
  MODIFY `transaction_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- AUTO_INCREMENT for table `transaction_items`
--
ALTER TABLE `transaction_items`
  MODIFY `item_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `attendance`
--
ALTER TABLE `attendance`
  ADD CONSTRAINT `attendance_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `employees`
--
ALTER TABLE `employees`
  ADD CONSTRAINT `employees_ibfk_1` FOREIGN KEY (`application_id`) REFERENCES `employee_applications` (`application_id`) ON DELETE SET NULL;

--
-- Constraints for table `payroll_periods`
--
ALTER TABLE `payroll_periods`
  ADD CONSTRAINT `payroll_periods_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `products`
--
ALTER TABLE `products`
  ADD CONSTRAINT `fk_product_category` FOREIGN KEY (`category_id`) REFERENCES `categories` (`category_id`) ON DELETE SET NULL;

--
-- Constraints for table `transaction_items`
--
ALTER TABLE `transaction_items`
  ADD CONSTRAINT `fk_ti_transaction` FOREIGN KEY (`transaction_id`) REFERENCES `transactions` (`transaction_id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
