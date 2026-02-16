# AMEO Okul Yönetim Sistemi

## Overview
AMEO (Okul Yönetim Sistemi) is a comprehensive, Flask-based Learning Management System (LMS) designed to manage educational operations for schools. It supports three distinct user roles: Admin, Teacher, and Student, each with tailored functionalities. The system facilitates core academic processes such as exam management, assignment distribution and collection, announcement dissemination, and internal messaging. The project aims to provide a robust, secure, and user-friendly platform for school administration, enhancing communication and academic tracking.

The system includes a full-featured practice exam tracking system for LGS (high school entrance exam in Turkey) with detailed performance analytics for students and teachers.

## User Preferences
I prefer iterative development with clear communication on changes. Please provide detailed explanations for significant modifications and ask for approval before implementing major architectural shifts. Ensure all existing functionalities are preserved unless explicitly requested for change. I expect the agent to fix identified bugs and complete requested features, ensuring full functionality across all user roles (Admin, Teacher, Student). All user-reported issues should be addressed comprehensively.

## System Architecture
The system is built on Python 3.11 with the Flask 3.1.2 framework. It uses a PostgreSQL database, managed by Replit. The frontend is developed using vanilla HTML, CSS, and JavaScript. Flask-Login handles user authentication, and Werkzeug's `secure_filename` is used for secure file handling.

**Key Architectural Decisions:**
- **Role-Based Access Control (RBAC):** Distinct panels and permissions for Admin, Teacher, and Student roles.
- **Modular Design:** Separation of concerns with dedicated templates and API endpoints for each major feature.
- **File Management:** Support for various file types (PDF, Excel, Images, Documents) with secure upload and inline viewing capabilities.
- **Database Connection Management:** Each function manages its own database connection for simplicity and stability, with future consideration for context manager patterns and connection pooling.
- **Security:** Implementation of `secure_filename()`, session security (httponly, samesite cookies), parameterized queries for SQL injection prevention, and RBAC.
- **Logging:** Integrated Python `logging` module for better error tracking and system monitoring.
- **UI/UX:** Responsive design for dashboards and forms. Chart.js is used for data visualization in student and teacher performance tracking. The system utilizes modals for interactive feedback, such as post-exam results.
- **Deployment:** Configured for Autoscale deployment using Gunicorn as the production WSGI server.

**Feature Specifications:**
- **Admin Panel:** User CRUD operations (including bulk import via Excel), class management (20 classes), teacher reports, file management, and system-wide announcements. Detailed system statistics and settings.
- **Teacher Panel:** Exam creation (PDF questions, Excel answer keys), assignment management, announcement publishing (with file/video support), student query responses, and performance reporting. Practice exam tracking with Excel import/export and graphical analysis.
- **Student Panel:** Exam viewing and submission, assignment submission, announcement viewing, teacher communication, grade/result access, and notifications. Personal statistics and progress graphs for practice exams.
- **LGS Practice Exam Tracking:** Comprehensive system for tracking student performance across 6 LGS subjects, supporting up to 50 practice exams per student, with detailed score, correct/incorrect/net counts, and LGS score calculation.

**Database Schema (Core Tables):**
- `users`: User information (admin/teacher/student)
- `classes`: Class definitions (e.g., 5A-8E)
- `exams`: Exam details and associated files
- `exam_submissions`: Student exam responses
- `exam_results`: Exam evaluation results
- `assignments`: Assignment definitions
- `assignment_submissions`: Submitted assignments
- `announcements`: General announcements
- `student_questions`: Student inquiries to teachers
- `practice_exams`: LGS practice exam records

## Recent Changes (2025-12-25)
- ✅ **Modal Uyarı Penceresi:** Toplu deneme yükleme sonuçları artık modal pencerede gösteriliyor, "Tamam" butonuna basılmadan kapanmıyor
- ✅ **Okul Numarası Desteği:** users tablosuna student_no sütunu eklendi
- ✅ **Gelişmiş Öğrenci Eşleştirme:** Excel yüklemede önce Sınıf+Ad Soyad, sonra student_no, sonra username ile eşleştirme yapılıyor
- ✅ **Bulunamayan Öğrenci Listesi:** Yüklemede bulunamayan öğrenciler modal pencerede listeleniyor

## Recent Changes (2025-12-09)
- ✅ **Kitap Kurdu Sistemi Yeniden Tasarlandı:** Yarışma bazlı sistemden 6 sabit sorulu sisteme geçildi
- ✅ **Yeni book_entries Tablosu:** Öğrenci kitap girişleri için JSONB cevaplarla yeni tablo
- ✅ **6 Sabit Soru:** Kitap adı, sayfa sayısı, en beğenilen bölüm, alternatif son, çıkarılan dersler, hikaye unsurları
- ✅ **Öğretmen Onay Sistemi:** Kitap girişleri öğretmen onayına tabi, onay/red gerekçesi ile
- ✅ **Liderlik Tablosu:** İlk 3'e rozet, tüm öğrenciler için sıralama görüntüleme
- ✅ **PDF Rapor:** Sınıf bazlı kitap kurdu raporu indirme özelliği
- ✅ **Detay Görüntüleme:** Öğretmenler liderlik tablosundan öğrenci kitap listelerini görebilir

## Recent Changes (2025-12-06)
- ✅ **Karne PDF Analiz Sistemi:** Optik yönetimi menüsüne yeni "Karne Analiz" sekmesi eklendi
- ✅ **PDF Yükleme ve Analiz:** Optik okuyucu yazılımından alınan karne PDF'leri yüklenebiliyor
- ✅ **Ders Bazlı Başarı Analizi:** Sistem ders bazlı başarı oranlarını hesaplıyor ve %50 altındaki dersleri tespit ediyor
- ✅ **Şube Karşılaştırma:** Şube bazlı ders başarı oranları karşılaştırmalı olarak raporlanıyor
- ✅ **PDF Rapor İndirme:** Analiz sonuçları otomatik olarak PDF raporu olarak indiriliyor
- ✅ **Study Plan System Redesigned:** Converted from form-based to PDF-based system - teachers upload PDF study plans, students view/download
- ✅ **New Database Table:** Added `study_plan_pdf` table for PDF study plan storage with target class or selected students support
- ✅ **Teacher Study Plan Page:** Redesigned with modern UI, PDF drag-drop upload, class or individual student selection, and delete functionality
- ✅ **Student Study Plan Page:** Redesigned to display assigned PDF study plans with view/download buttons using `window.open(_blank)` for APK compatibility
- ✅ **Consistent File Viewing:** All file viewing now uses `window.open(_blank)` method for compatibility across APK and computer browsers

## Recent Changes (2025-12-02)
- ✅ **Comprehensive UI/UX Modernization:** Applied consistent modern design system across all panels (Admin, Teacher, Student, Parent)
- ✅ **CSS Design System:** Implemented `admin-modern.css` with CSS variables for colors, gradients, shadows, and animations
- ✅ **Student Pages Modernized:** Converted student_assignments, student_announcements, student_ask_question, student_exams, student_surveys, student_study_plan, student_lesson_schedule to base_dashboard structure
- ✅ **Standalone Pages Updated:** Added modern CSS variables to student_practice_exams, student_book_worm, student_daily_tracking, teacher_practice_exams, admin_practice_exams, teacher_book_worm, teacher_daily_tracking, teacher_lesson_schedule, admin_lesson_schedule
- ✅ **Parent Dashboard Modernized:** Applied modern card styles and button designs
- ✅ **Fixed Admin Files 500 Error:** Added proper Object Storage path handling and None value checks

## Recent Changes (2025-11-28)
- ✅ **Fixed PDF Open Issue (APK):** Implemented PDF → PNG conversion using `pdftoppm` subprocess. Reports now download as PNG files which APK can open (PDF support was missing)
- ✅ **LGS Score Sorting:** Student list sorted by LGS score descending (highest score first)
- ✅ **PDF Report Stability:** Removed RotatedParagraph class that caused PDF corruption; using multi-line text instead
- ✅ **APK Password Persistence Guide:** Created `APK_PASSWORD_PERSISTENCE.md` with TinyDB/SharedPreferences implementation steps for auto-login

## Known Issues & Workarounds
- **APK PDF Opening:** Resolved - Now returns PNG format instead of PDF
- **APK Password Persistence:** Requires Kodular implementation using TinyDB component (see `APK_PASSWORD_PERSISTENCE.md`)

## External Dependencies
- **PostgreSQL:** Primary database for all application data.
- **Flask:** Web framework.
- **Flask-Login:** User session management.
- **psycopg2-binary:** PostgreSQL database adapter for Python.
- **pandas:** Data manipulation and analysis, primarily for Excel operations.
- **openpyxl:** Library for reading and writing Excel files.
- **python-dotenv:** For managing environment variables.
- **Werkzeug:** Utilized for secure file handling (`secure_filename`).
- **reportlab:** PDF generation with Turkish character support (DejaVuSans font).
- **pdf2image:** PDF to image conversion support.
- **Pillow (PIL):** Image processing library.
- **Chart.js:** JavaScript library for data visualization.
- **matplotlib:** Chart generation for Python analytics.
- **google-cloud-storage:** Object storage integration.
- **replit.object_storage:** Replit native object storage client.