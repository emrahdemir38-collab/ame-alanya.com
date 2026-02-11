--
-- PostgreSQL database dump
--

\restrict GhrzuMCoqKEaFrlu1A77NqiWeLDSU1lg5WDvDEUZUAPvJNsrlKUjUmB6IZpmbft

-- Dumped from database version 16.11 (df20cf9)
-- Dumped by pg_dump version 16.10

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: assignments; Type: TABLE DATA; Schema: public; Owner: neondb_owner
--

COPY public.assignments (id, title, description, file_path, video_url, due_date, target_class, teacher_id, created_at) FROM stdin;
\.


--
-- Data for Name: exams; Type: TABLE DATA; Schema: public; Owner: neondb_owner
--

COPY public.exams (id, title, question_count, start_time, duration_minutes, pdf_filename, answer_key, target_class, teacher_id, created_at, allow_pause, end_time) FROM stdin;
\.


--
-- Data for Name: exam_results; Type: TABLE DATA; Schema: public; Owner: neondb_owner
--

COPY public.exam_results (id, exam_id, student_id, answers, score, submitted_at) FROM stdin;
\.


--
-- Data for Name: exam_submissions; Type: TABLE DATA; Schema: public; Owner: neondb_owner
--

COPY public.exam_submissions (id, exam_id, student_id, answers, score, submitted_at, status, started_at) FROM stdin;
\.


--
-- Name: assignments_id_seq; Type: SEQUENCE SET; Schema: public; Owner: neondb_owner
--

SELECT pg_catalog.setval('public.assignments_id_seq', 2, true);


--
-- Name: exam_results_id_seq; Type: SEQUENCE SET; Schema: public; Owner: neondb_owner
--

SELECT pg_catalog.setval('public.exam_results_id_seq', 1, false);


--
-- Name: exam_submissions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: neondb_owner
--

SELECT pg_catalog.setval('public.exam_submissions_id_seq', 1, false);


--
-- PostgreSQL database dump complete
--

\unrestrict GhrzuMCoqKEaFrlu1A77NqiWeLDSU1lg5WDvDEUZUAPvJNsrlKUjUmB6IZpmbft

