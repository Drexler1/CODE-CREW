CODE CREW Point of Sale System
==============================

This repository contains a simple Point of Sale (POS) web application built with Python and Flask.

Project structure:
- app.py: main application entry point
- database/ : SQL database files and schema definitions
- static/ : static assets, images, and face data
- templates/ : HTML templates for admin, cashier, and error pages

Getting started:
1. Create and activate a Python virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Run `python app.py` to start the application.
4. Open the local web browser at `http://127.0.0.1:5000`.

Features:
- Admin dashboard and settings
- Inventory and product management
- Sales and transaction tracking
- Employee payroll and attendance

Purpose of the Project

The primary purpose of this capstone project is to develop and implement a Smart POS Cafe Management System for Books and Blooms Cafe. This system transitions the establishment from high-risk manual processes into a secure, automated, and unified digital framework. 

The project is engineered to achieve three core system purposes:

1. Enforce Data Integrity in Human Capital Management
By replacing vulnerable manual paper logbooks and group chat photo submissions with a software-driven Face Recognition Attendance System (built via FaceNet-512 and OpenCV), this project establishes non-repudiation. It guarantees that employee clock-in/out timestamps are completely authentic, accurate, and immune to manual manipulation or identity fraud (buddy punching).

2. Eliminate Financial Leaks Through Automated Payroll Processing
This project creates a direct, real-time data pipeline between biometric attendance logs and the rate database. By automating the mathematical computation of regular hours worked, overtime metrics, and late arrival deductions, the system completely removes human computational fatigue and ensures precise, error-free wage generation for the cafe owner.

3. Optimize Physical Capital Control via Automated Inventory Mapping
Because Books and Blooms Cafe operates as a unique hybrid establishment (managing coffee ingredients, books, and floral arrangements simultaneously), this project integrates a centralized Internal Inventory Control Module. This automates material tracking, updates item stocks in real-time, and triggers low-stock alert thresholds, allowing the administrator to manage both human and physical capital from a single unified ecosystem.
