--
-- PostgreSQL database dump
--

\restrict eiYEGRl5e5am0mYkX9Cl0Rcphle1E2P71La8vc9pdTPLnz9wdf2HOokpXiccGcV

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
-- Data for Name: classes; Type: TABLE DATA; Schema: public; Owner: neondb_owner
--

COPY public.classes (id, name, level, branch, type, is_active, created_at) FROM stdin;
15	5A	5	A	standard	t	2025-10-26 16:30:59.942359
16	5B	5	B	standard	t	2025-10-26 16:30:59.942359
17	5C	5	C	standard	t	2025-10-26 16:30:59.942359
18	5D	5	D	standard	t	2025-10-26 16:30:59.942359
19	5E	5	E	standard	t	2025-10-26 16:30:59.942359
20	6A	6	A	standard	t	2025-10-26 16:30:59.942359
21	6B	6	B	standard	t	2025-10-26 16:30:59.942359
22	6C	6	C	standard	t	2025-10-26 16:30:59.942359
23	6D	6	D	standard	t	2025-10-26 16:30:59.942359
24	6E	6	E	standard	t	2025-10-26 16:30:59.942359
25	7A	7	A	standard	t	2025-10-26 16:30:59.942359
26	7B	7	B	standard	t	2025-10-26 16:30:59.942359
27	7C	7	C	standard	t	2025-10-26 16:30:59.942359
28	7D	7	D	standard	t	2025-10-26 16:30:59.942359
29	7E	7	E	standard	t	2025-10-26 16:30:59.942359
30	8A	8	A	standard	t	2025-10-26 16:30:59.942359
31	8B	8	B	standard	t	2025-10-26 16:30:59.942359
32	8C	8	C	standard	t	2025-10-26 16:30:59.942359
33	8D	8	D	standard	t	2025-10-26 16:30:59.942359
34	8E	8	E	standard	t	2025-10-26 16:30:59.942359
\.


--
-- Data for Name: exams; Type: TABLE DATA; Schema: public; Owner: neondb_owner
--

COPY public.exams (id, title, question_count, start_time, duration_minutes, pdf_filename, answer_key, target_class, teacher_id, created_at, allow_pause, end_time) FROM stdin;
\.


--
-- Data for Name: teacher_classes; Type: TABLE DATA; Schema: public; Owner: neondb_owner
--

COPY public.teacher_classes (id, teacher_id, class_name, assigned_date) FROM stdin;
1	785	5A	2026-01-24 17:46:52.338383
2	785	5/A	2026-01-24 17:46:52.338383
3	785	5B	2026-01-24 17:46:52.338383
4	785	5/B	2026-01-24 17:46:52.338383
5	785	5/C	2026-01-24 17:46:52.338383
6	785	5/D	2026-01-24 17:46:52.338383
7	785	6A	2026-01-24 17:46:52.338383
8	785	6C	2026-01-24 17:46:52.338383
9	785	6D	2026-01-24 17:46:52.338383
10	785	7/A	2026-01-24 17:46:52.338383
11	785	7/B	2026-01-24 17:46:52.338383
12	785	7B	2026-01-24 17:46:52.338383
13	785	7/C	2026-01-24 17:46:52.338383
14	785	7/D	2026-01-24 17:46:52.338383
15	785	8A	2026-01-24 17:46:52.338383
16	785	8B	2026-01-24 17:46:52.338383
17	785	8C	2026-01-24 17:46:52.338383
18	785	8D	2026-01-24 17:46:52.338383
19	785	5C	2026-01-24 17:47:31.322556
20	785	5D	2026-01-24 17:47:31.322556
21	785	5E	2026-01-24 17:47:31.322556
22	785	6B	2026-01-24 17:47:31.322556
23	785	6E	2026-01-24 17:47:31.322556
24	785	7A	2026-01-24 17:47:31.322556
25	785	7C	2026-01-24 17:47:31.322556
26	785	7D	2026-01-24 17:47:31.322556
27	785	7E	2026-01-24 17:47:31.322556
28	785	8E	2026-01-24 17:47:31.322556
\.


--
-- Name: classes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: neondb_owner
--

SELECT pg_catalog.setval('public.classes_id_seq', 34, true);


--
-- Name: teacher_classes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: neondb_owner
--

SELECT pg_catalog.setval('public.teacher_classes_id_seq', 58, true);


--
-- PostgreSQL database dump complete
--

\unrestrict eiYEGRl5e5am0mYkX9Cl0Rcphle1E2P71La8vc9pdTPLnz9wdf2HOokpXiccGcV

