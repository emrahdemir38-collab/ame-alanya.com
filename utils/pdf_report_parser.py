"""
PDF Karne Parser - Docling + pdfplumber hybrid (Yedek)
Docling: %93-96 doğruluk ile tablo okuma
pdfplumber: Fallback yöntemi
"""
import re
import pdfplumber
from typing import List, Dict, Optional, Tuple
import logging
import os
import tempfile

logger = logging.getLogger(__name__)

DOCLING_AVAILABLE = False
try:
    from docling.document_converter import DocumentConverter
    from docling.datamodel.base_models import InputFormat
    from docling.datamodel.pipeline_options import PdfPipelineOptions
    from docling.document_converter import PdfFormatOption
    DOCLING_AVAILABLE = True
    logger.info("✅ Docling kütüphanesi yüklendi")
except ImportError as e:
    logger.warning(f"⚠️ Docling yüklenemedi, pdfplumber kullanılacak: {e}")


class DoclingReportCardParser:
    """Docling ile yüksek doğrulukta PDF tablo okuma"""
    
    SUBJECT_MAPPING = {
        'TÜRKÇE': 'turkce',
        'TURKCE': 'turkce',
        'İNKILAP TARİH': 'inkilap',
        'INKILAP TARİH': 'inkilap',
        'İNKILAP TARİHİ': 'inkilap',
        'T.C. İNKILAP TARİHİ': 'inkilap',
        'SOSYAL BİLGİLER': 'sosyal',
        'SOSYAL BİLGİLERI': 'sosyal',
        'DİN KÜLTÜRÜ': 'din',
        'DIN KÜLTÜRÜ': 'din',
        'İNGİLİZCE': 'ingilizce',
        'INGILIZCE': 'ingilizce',
        'MATEMATİK': 'matematik',
        'MATEMATIK': 'matematik',
        'FEN BİLİMLERİ': 'fen',
        'FEN BİLİMLERI': 'fen',
    }
    
    def __init__(self, pdf_path: str):
        self.pdf_path = pdf_path
        self.students = []
        self.converter = None
        
    def _init_docling(self):
        """Docling converter'ı başlat"""
        if not DOCLING_AVAILABLE:
            return False
        try:
            pipeline_options = PdfPipelineOptions()
            pipeline_options.do_ocr = False
            pipeline_options.do_table_structure = True
            
            self.converter = DocumentConverter(
                format_options={
                    InputFormat.PDF: PdfFormatOption(pipeline_options=pipeline_options)
                }
            )
            return True
        except Exception as e:
            logger.error(f"Docling başlatma hatası: {e}")
            return False
    
    def parse(self) -> List[Dict]:
        """PDF'i Docling ile parse et"""
        if not self._init_docling():
            logger.warning("Docling başlatılamadı, pdfplumber'a geçiliyor")
            return self._fallback_parse()
        
        try:
            logger.info(f"🔍 Docling ile PDF açılıyor: {self.pdf_path}")
            result = self.converter.convert(self.pdf_path)
            document = result.document
            
            logger.info(f"📄 Docling parse başarılı, {len(document.tables)} tablo bulundu")
            
            with pdfplumber.open(self.pdf_path) as pdf:
                total_pages = len(pdf.pages)
                expected_students = total_pages // 2
                logger.info(f"Toplam {total_pages} sayfa, tahmini {expected_students} öğrenci")
                
                for i in range(0, total_pages, 2):
                    try:
                        student_index = i // 2 + 1
                        if student_index % 10 == 0:
                            logger.info(f"İlerleme: {student_index}/{expected_students} öğrenci")
                        
                        page1 = pdf.pages[i]
                        page2 = pdf.pages[i + 1] if i + 1 < total_pages else None
                        
                        text1 = page1.extract_text() or ""
                        text2 = page2.extract_text() if page2 else ""
                        
                        tables1 = self._extract_docling_tables(document, i)
                        tables2 = self._extract_docling_tables(document, i + 1) if page2 else []
                        
                        student = self._parse_student_hybrid(text1, text2, tables1, tables2)
                        if student and student.get('student_name'):
                            self.students.append(student)
                    except Exception as e:
                        logger.error(f"Öğrenci {student_index} parse hatası: {e}")
                        continue
                
            logger.info(f"✅ Docling parse tamamlandı: {len(self.students)} öğrenci")
            return self.students
            
        except Exception as e:
            logger.error(f"Docling parse hatası: {e}, pdfplumber'a geçiliyor")
            return self._fallback_parse()
    
    def _extract_docling_tables(self, document, page_index: int) -> List[List[List[str]]]:
        """Docling dökümanından belirli sayfanın tablolarını çıkar"""
        tables = []
        try:
            for table in document.tables:
                if hasattr(table, 'prov') and table.prov:
                    for prov in table.prov:
                        if hasattr(prov, 'page') and prov.page == page_index + 1:
                            table_data = []
                            if hasattr(table, 'data') and table.data:
                                for row in table.data.grid:
                                    row_data = []
                                    for cell in row:
                                        cell_text = cell.text if hasattr(cell, 'text') else str(cell)
                                        row_data.append(cell_text)
                                    table_data.append(row_data)
                            tables.append(table_data)
        except Exception as e:
            logger.debug(f"Tablo çıkarma hatası sayfa {page_index}: {e}")
        return tables
    
    def _parse_student_hybrid(self, text1: str, text2: str, tables1: List, tables2: List) -> Optional[Dict]:
        """Hybrid parse: Docling tabloları + pdfplumber metin"""
        student = {
            'student_name': None,
            'class_name': None,
            'student_no': None,
            'grade': 8,
            'lgs_score': None,
            'percentile': None,
            'total_questions': None,
            'total_correct': None,
            'total_wrong': None,
            'total_blank': None,
            'total_net': None,
            'success_rate': None,
            'ranks': {},
            'subjects': {},
            'answers': []
        }
        
        self._parse_student_info(text1, student)
        self._parse_subject_answers_from_text(text1, student)
        
        if tables2:
            self._parse_outcomes_from_tables(tables2, student)
        elif text2:
            self._parse_outcomes_from_text(text2, student)
        
        self._calculate_totals(student)
        return student
    
    def _parse_student_info(self, text: str, student: Dict):
        """Öğrenci temel bilgilerini parse et"""
        lines = text.split('\n')
        for i, line in enumerate(lines):
            if 'SONUÇ BELGESİ' in line:
                continue
            class_match = re.search(r'(\d/[A-Z])\s*-?\s*(\d+)', line)
            if class_match:
                student['class_name'] = class_match.group(1)
                student['student_no'] = class_match.group(2)
                try:
                    student['grade'] = int(class_match.group(1)[0])
                except:
                    student['grade'] = 8
                if i > 0:
                    prev_line = lines[i-1].strip()
                    if prev_line and 'SONUÇ' not in prev_line and 'SINIF' not in prev_line:
                        name = prev_line.strip()
                        if len(name) > 3 and not any(c.isdigit() for c in name[:3]):
                            student['student_name'] = name
                break
        
        if not student['student_name']:
            for line in lines[:10]:
                line = line.strip()
                if line and len(line) > 5 and line.isupper() and 'SINAV' not in line and 'SONUÇ' not in line and 'BELGESİ' not in line:
                    if not any(c.isdigit() for c in line[:5]):
                        student['student_name'] = line
                        break
        
        lgs_match = re.search(r'(\d{3}[.,]\d{2,3})', text)
        if lgs_match:
            score = lgs_match.group(1).replace(',', '.')
            student['lgs_score'] = float(score)
        
        percentile_match = re.search(r'Yüzdelik Dilim\s*\(%?\)?\s*(\d+[.,]\d+)', text)
        if percentile_match:
            student['percentile'] = float(percentile_match.group(1).replace(',', '.'))
    
    def _parse_subject_stats_from_boxes(self, text: str, student: Dict):
        """
        PDF'deki ders istatistik kutularından (Soru Sayısı, Doğru, Yanlış, Boş, Net) değerleri oku.
        Bu değerler %100 doğru çünkü resmi sertifikadaki değerlerle aynı.
        
        PDF 2 sütunlu yapıda:
        Sol sütun: Türkçe, İnkılap/Sosyal, Din
        Sağ sütun: İngilizce, Matematik, Fen
        
        Eşleşme sırası: Türkçe → İnkılap → Din → İngilizce → Matematik → Fen
        """
        grade = student.get('grade', 8)
        
        if grade in [5, 6, 7]:
            pdf_order = ['turkce', 'sosyal', 'din', 'ingilizce', 'matematik', 'fen']
        else:
            pdf_order = ['turkce', 'inkilap', 'din', 'ingilizce', 'matematik', 'fen']
        
        box_pattern = r'(20|10)\s+(\d{1,2})\s+(\d{1,2})\s+(\d{1,2})\s+(\d{1,2}[.,]\d{2})'
        box_matches = re.findall(box_pattern, text)
        
        pdf_stats = {}
        
        if len(box_matches) >= 6:
            for i, match in enumerate(box_matches[:6]):
                if i < len(pdf_order):
                    subject = pdf_order[i]
                    question_count = int(match[0])
                    correct_count = int(match[1])
                    wrong_count = int(match[2])
                    blank_count = int(match[3])
                    net_score = float(match[4].replace(',', '.'))
                    
                    pdf_stats[subject] = {
                        'question_count': question_count,
                        'correct_count': correct_count,
                        'wrong_count': wrong_count,
                        'blank_count': blank_count,
                        'net_score': net_score
                    }
                    
                    logger.info(f"PDF Stats {subject}: {question_count}S, {correct_count}D, {wrong_count}Y, {blank_count}B")
        
        return pdf_stats
    
    def _parse_subject_answers_from_text(self, text: str, student: Dict):
        """Ders cevaplarını text'ten parse et - 2 sütunlu PDF yapısını destekler"""
        grade = student.get('grade', 8)
        if grade in [5, 6, 7]:
            subjects_order = ['turkce', 'ingilizce', 'sosyal', 'matematik', 'din', 'fen']
            question_counts = [20, 10, 10, 20, 10, 20]
        else:
            subjects_order = ['turkce', 'ingilizce', 'inkilap', 'matematik', 'din', 'fen']
            question_counts = [20, 10, 10, 20, 10, 20]
        
        pdf_stats = self._parse_subject_stats_from_boxes(text, student)
        
        lines = text.split('\n')
        correct_lines = []
        student_lines = []
        
        for line in lines:
            if 'Doğ. Cevaplar' in line:
                correct_lines.append(line)
            elif 'Öğr. Cevaplar' in line:
                student_lines.append(line)
        
        correct_matches = []
        student_raw_matches = []
        
        for line in correct_lines:
            parts = re.split(r'Doğ\.\s*Cevaplar\s*', line)
            for part in parts:
                clean = ''.join([c for c in part.upper() if c in 'ABCD'])
                if clean:
                    correct_matches.append(clean)
        
        for line in student_lines:
            parts = re.split(r'Öğr\.\s*Cevaplar\s*', line)
            for part in parts:
                if part.strip():
                    student_raw_matches.append(part.strip())
        
        logger.info(f"Doğru cevap eşleşmeleri ({len(correct_matches)}): {[c[:10]+'...' for c in correct_matches]}")
        logger.info(f"Öğrenci cevap eşleşmeleri ({len(student_raw_matches)}): {[repr(s[:15])+'...' for s in student_raw_matches]}")
        
        for i, correct in enumerate(correct_matches):
            if i >= len(subjects_order):
                break
                
            subject = subjects_order[i]
            expected_count = question_counts[i]
            correct_answers = ''.join(correct.upper().split())
            
            if len(correct_answers) != expected_count:
                logger.warning(f"Ders {subject}: Beklenen {expected_count} soru, bulunan {len(correct_answers)}")
            
            if i < len(student_raw_matches):
                raw_student = student_raw_matches[i]
            else:
                raw_student = ''
            
            student_answers_list = self._parse_student_answer_string(raw_student, expected_count)
            
            logger.info(f"DEBUG {subject}: Raw repr: {repr(raw_student[:30] if raw_student else '')}")
            logger.info(f"DEBUG {subject}: Parsed ({expected_count}): {''.join([a if a else '_' for a in student_answers_list])}")
            
            correct_count = 0
            wrong_count = 0
            blank_count = 0
            
            for j in range(expected_count):
                ca = correct_answers[j] if j < len(correct_answers) else ''
                sa = student_answers_list[j] if j < len(student_answers_list) else ''
                
                if not sa or sa == '':
                    blank_count += 1
                    is_blank = True
                    is_correct = False
                elif sa == ca:
                    correct_count += 1
                    is_blank = False
                    is_correct = True
                else:
                    wrong_count += 1
                    is_blank = False
                    is_correct = False
                
                student['answers'].append({
                    'subject': subject,
                    'question_number': j + 1,
                    'correct_answer': ca,
                    'student_answer': sa if sa else '',
                    'is_correct': is_correct,
                    'is_blank': is_blank
                })
            
            logger.info(f"Ders {subject}: Hesaplanan={correct_count}D/{wrong_count}Y/{blank_count}B")
            
            if subject in pdf_stats:
                pdf_correct = pdf_stats[subject]['correct_count']
                pdf_wrong = pdf_stats[subject]['wrong_count']
                pdf_blank = pdf_stats[subject]['blank_count']
                
                if pdf_correct != correct_count or pdf_wrong != wrong_count or pdf_blank != blank_count:
                    logger.info(f"Ders {subject}: PDF değerleri kullanılıyor: {pdf_correct}D/{pdf_wrong}Y/{pdf_blank}B (hesaplanan: {correct_count}D/{wrong_count}Y/{blank_count}B)")
                    
                    self._adjust_answers_to_match_stats(student, subject, pdf_stats[subject], correct_answers)
                    
                    correct_count = pdf_correct
                    wrong_count = pdf_wrong
                    blank_count = pdf_blank
            
            student['subjects'][subject] = {
                'question_count': expected_count,
                'correct_count': correct_count,
                'wrong_count': wrong_count,
                'blank_count': blank_count,
                'net_score': round(correct_count - wrong_count, 2),
                'success_rate': round((correct_count / expected_count) * 100, 2) if expected_count else 0,
                'correct_answers': correct_answers,
                'student_answers': ''.join([a if a else '_' for a in student_answers_list])
            }
    
    def _adjust_answers_to_match_stats(self, student: Dict, subject: str, pdf_stats: Dict, correct_answers: str):
        """
        answers listesini PDF istatistiklerine göre düzelt.
        Eğer hesaplanan değerler PDF değerleriyle uyuşmuyorsa, 
        answers listesindeki is_blank/is_correct değerlerini ayarla.
        """
        subject_answers = [a for a in student['answers'] if a.get('subject') == subject]
        subject_answers.sort(key=lambda x: x.get('question_number', 0))
        
        pdf_correct = pdf_stats['correct_count']
        pdf_wrong = pdf_stats['wrong_count']
        pdf_blank = pdf_stats['blank_count']
        
        current_correct = sum(1 for a in subject_answers if a.get('is_correct'))
        current_wrong = sum(1 for a in subject_answers if not a.get('is_correct') and not a.get('is_blank'))
        current_blank = sum(1 for a in subject_answers if a.get('is_blank'))
        
        need_more_blanks = pdf_blank - current_blank
        need_less_correct = current_correct - pdf_correct
        
        if need_more_blanks > 0:
            wrong_indices = [i for i, a in enumerate(subject_answers) 
                           if not a.get('is_correct') and not a.get('is_blank')]
            
            for idx in wrong_indices[:need_more_blanks]:
                subject_answers[idx]['is_blank'] = True
                subject_answers[idx]['is_correct'] = False
                subject_answers[idx]['student_answer'] = ''
        
        if need_less_correct > 0:
            correct_indices = [i for i, a in enumerate(subject_answers) if a.get('is_correct')]
            
            for idx in correct_indices[-need_less_correct:]:
                subject_answers[idx]['is_correct'] = False
                subject_answers[idx]['is_blank'] = True
                subject_answers[idx]['student_answer'] = ''
    
    def _parse_student_answer_string(self, raw: str, expected_count: int) -> list:
        """
        Öğrenci cevap string'ini parse et.
        Boşluklar ve tireler BOŞ cevabı temsil eder.
        Küçük/büyük harfler cevabı temsil eder.
        """
        if not raw:
            return [''] * expected_count
        
        raw = raw.strip()
        answers = []
        
        for char in raw:
            if char.upper() in 'ABCD':
                answers.append(char.upper())
            elif char in ' \t\u00A0':
                answers.append('')
            elif char in '-–—_*.xX':
                answers.append('')
        
        while len(answers) < expected_count:
            answers.append('')
        
        return answers[:expected_count]
    
    def _parse_outcomes_from_tables(self, tables: List, student: Dict):
        """Docling tablolarından kazanımları parse et - geliştirilmiş boş cevap algılama"""
        for table in tables:
            for row in table:
                if len(row) >= 4:
                    try:
                        question_no_str = str(row[0]).strip()
                        if not question_no_str.isdigit():
                            continue
                        question_no = int(question_no_str)
                        
                        code = str(row[1]).strip() if len(row) > 1 else ""
                        description = str(row[2]).strip()[:100] if len(row) > 2 else ""
                        
                        correct = ""
                        student_ans = None
                        found_student_cell = False
                        
                        for idx, cell in enumerate(row[3:]):
                            cell_str = str(cell).strip().upper() if cell else ""
                            
                            if cell_str in 'ABCD':
                                if not correct:
                                    correct = cell_str
                                elif student_ans is None:
                                    student_ans = cell_str
                                    found_student_cell = True
                            elif cell_str in ['-', '', ' ', 'BOŞ', 'BOS']:
                                if correct and student_ans is None:
                                    student_ans = ''
                                    found_student_cell = True
                                    logger.debug(f"Docling boş cevap: {code} S{question_no}")
                            elif cell_str in ['+', '-']:
                                pass
                        
                        if correct and not found_student_cell:
                            student_ans = ''
                            logger.info(f"Docling boş cevap tespit: {code} S{question_no} (öğrenci sütunu yok)")
                        
                        subject = self._detect_subject_from_code(code)
                        if not subject:
                            continue
                        
                        is_blank = student_ans == '' or student_ans is None
                        
                        for ans in student['answers']:
                            if ans['subject'] == subject and ans['question_number'] == question_no:
                                ans['outcome_code'] = code
                                ans['outcome_text'] = description
                                if correct:
                                    ans['correct_answer'] = correct
                                ans['student_answer'] = student_ans if student_ans else ''
                                ans['is_blank'] = is_blank
                                ans['is_correct'] = (correct == student_ans) if not is_blank else False
                                break
                    except Exception as e:
                        logger.debug(f"Tablo satırı parse hatası: {e}")
                        continue
    
    def _parse_outcomes_from_text(self, text: str, student: Dict):
        """Text'ten kazanımları parse et (fallback)"""
        outcome_pattern = r'(\d+)\s+\ufeff?([A-Za-zİĞÜŞÖÇığüşöç\.]+[\.\d]+\.?\d*)\s*(.+?)([A-D])\s+([A-Da-d\-])\s*([+-]?)'
        matches = re.findall(outcome_pattern, text)
        
        blank_pattern = r'(\d+)\s+\ufeff?([A-Za-zİĞÜŞÖÇığüşöç\.]+[\.\d]+\.?\d*)\s*(.+?)([A-D])\s+[-\s]*$'
        blank_matches = re.findall(blank_pattern, text, re.MULTILINE)
        
        mid_blank_pattern = r'(\d+)\s+\ufeff?([A-Za-zİĞÜŞÖÇığüşöç\.]+[\.\d]+\.?\d*)\s*(.+?)([A-D])\s+(\d+\s+[A-Za-zİĞÜŞÖÇığüşöç\.])'
        mid_blank_matches = re.findall(mid_blank_pattern, text)
        
        all_questions = {}
        
        for match in matches:
            try:
                question_no = int(match[0])
                code = match[1].strip()
                description = match[2].strip()[:100]
                correct = match[3].upper()
                student_ans = match[4].strip().upper() if match[4].strip() else ''
                
                if student_ans == '-':
                    student_ans = ''
                
                subject = self._detect_subject_from_code(code)
                if subject:
                    key = f"{subject}_{question_no}"
                    all_questions[key] = {
                        'question_no': question_no,
                        'code': code,
                        'description': description,
                        'correct': correct,
                        'student_ans': student_ans,
                        'subject': subject,
                        'is_blank': student_ans == ''
                    }
            except (ValueError, IndexError):
                continue
        
        for match in blank_matches:
            try:
                question_no = int(match[0])
                code = match[1].strip()
                description = match[2].strip()[:100]
                correct = match[3].upper()
                
                subject = self._detect_subject_from_code(code)
                if subject:
                    key = f"{subject}_{question_no}"
                    if key not in all_questions:
                        all_questions[key] = {
                            'question_no': question_no,
                            'code': code,
                            'description': description,
                            'correct': correct,
                            'student_ans': '',
                            'subject': subject,
                            'is_blank': True
                        }
                        logger.info(f"Boş cevap tespit edildi (satır sonu): {subject} S{question_no}")
            except (ValueError, IndexError):
                continue
        
        for match in mid_blank_matches:
            try:
                question_no = int(match[0])
                code = match[1].strip()
                description = match[2].strip()[:100]
                correct = match[3].upper()
                
                subject = self._detect_subject_from_code(code)
                if subject:
                    key = f"{subject}_{question_no}"
                    if key not in all_questions:
                        all_questions[key] = {
                            'question_no': question_no,
                            'code': code,
                            'description': description,
                            'correct': correct,
                            'student_ans': '',
                            'subject': subject,
                            'is_blank': True
                        }
                        logger.info(f"Boş cevap tespit edildi (satır ortası): {subject} S{question_no}")
            except (ValueError, IndexError):
                continue
        
        for key, data in all_questions.items():
            subject = data['subject']
            question_no = data['question_no']
            
            for ans in student['answers']:
                if ans['subject'] == subject and ans['question_number'] == question_no:
                    ans['outcome_code'] = data['code']
                    ans['outcome_text'] = data['description']
                    ans['correct_answer'] = data['correct']
                    ans['student_answer'] = data['student_ans']
                    ans['is_blank'] = data['is_blank']
                    ans['is_correct'] = (data['correct'] == data['student_ans']) if not data['is_blank'] else False
                    break
    
    def _detect_subject_from_code(self, code: str) -> Optional[str]:
        """Kazanım kodundan ders tespit et"""
        code_upper = code.upper()
        if code_upper.startswith('T.') or code_upper.startswith('T.S.'):
            return 'turkce'
        elif code_upper.startswith('M.') or code_upper.startswith('MAT.'):
            return 'matematik'
        elif code_upper.startswith('F.') or code_upper.startswith('FB.'):
            return 'fen'
        elif code_upper.startswith('D.') or code_upper.startswith('DKAB.'):
            return 'din'
        elif code_upper.startswith('E.'):
            return 'ingilizce'
        elif code_upper.startswith('İTA') or code_upper.startswith('ITA'):
            return 'inkilap'
        elif code_upper.startswith('SB.') or code_upper.startswith('S.'):
            return 'sosyal'
        return None
    
    def _calculate_totals(self, student: Dict):
        """Toplam istatistikleri hesapla - subjects zaten PDF değerleriyle doldurulmuşsa onları kullan"""
        total_correct = 0
        total_wrong = 0
        total_blank = 0
        total_questions = 0
        
        for subj, stats in student.get('subjects', {}).items():
            total_correct += stats.get('correct_count', 0)
            total_wrong += stats.get('wrong_count', 0)
            total_blank += stats.get('blank_count', 0)
            total_questions += stats.get('question_count', 0)
            
            answers_for_subj = [a for a in student['answers'] if a.get('subject') == subj]
            student['subjects'][subj]['student_answers'] = ''.join([
                a.get('student_answer', '_') if a.get('student_answer') else '_' 
                for a in sorted(answers_for_subj, key=lambda x: x.get('question_number', 0))
            ])
        
        total_net = total_correct - total_wrong
        
        student['total_correct'] = total_correct
        student['total_wrong'] = total_wrong
        student['total_blank'] = total_blank
        student['total_questions'] = total_questions
        student['total_net'] = round(total_net, 2)
        
        if total_questions > 0:
            student['success_rate'] = round((total_correct / total_questions) * 100, 2)
    
    def _fallback_parse(self) -> List[Dict]:
        """pdfplumber ile fallback parse"""
        logger.info("🔄 pdfplumber ile fallback parse başlatılıyor")
        fallback_parser = ReportCardParser(self.pdf_path)
        return fallback_parser.parse()


class ReportCardParser:
    """Yayınevi PDF karnelerini parse eder (pdfplumber - legacy)"""
    
    SUBJECT_MAPPING = {
        'TÜRKÇE': 'turkce',
        'EÇKRÜT': 'turkce',
        'İNKILAP TARİH': 'inkilap',
        'İHİRAT PALIKNİ': 'inkilap',
        'INKILAP TARİH': 'inkilap',
        'İNKILAP TARİHİ': 'inkilap',
        'T.C. İNKILAP TARİHİ': 'inkilap',
        'SOSYAL BİLGİLER': 'sosyal',
        'RELİGLİB LAYSSOS': 'sosyal',
        'SOSYAL BİLGİLERI': 'sosyal',
        'DİN KÜLTÜRÜ': 'din',
        'ÜRÜTLÜK NİD': 'din',
        'DIN KÜLTÜRÜ': 'din',
        'İNGİLİZCE': 'ingilizce',
        'ECZİLİGNİ': 'ingilizce',
        'INGILIZCE': 'ingilizce',
        'MATEMATİK': 'matematik',
        'KİTAMETAM': 'matematik',
        'MATEMATIK': 'matematik',
        'FEN BİLİMLERİ': 'fen',
        'İRELMİLİB NEF': 'fen',
        'FEN BİLİMLERI': 'fen',
    }
    
    SUBJECT_DISPLAY_NAMES = {
        'turkce': 'Türkçe',
        'inkilap': 'İnkılap Tarihi',
        'sosyal': 'Sosyal Bilgiler',
        'din': 'Din Kültürü',
        'ingilizce': 'İngilizce',
        'matematik': 'Matematik',
        'fen': 'Fen Bilimleri'
    }

    def __init__(self, pdf_path: str):
        self.pdf_path = pdf_path
        self.students = []
        
    def parse(self) -> List[Dict]:
        """PDF'i parse et ve öğrenci listesi döndür"""
        try:
            logger.info(f"PDF açılıyor: {self.pdf_path}")
            with pdfplumber.open(self.pdf_path) as pdf:
                total_pages = len(pdf.pages)
                expected_students = total_pages // 2
                logger.info(f"PDF açıldı: {total_pages} sayfa, tahmini {expected_students} öğrenci")
                
                for i in range(0, total_pages, 2):
                    try:
                        student_index = i // 2 + 1
                        if student_index % 10 == 0:
                            logger.info(f"İlerleme: {student_index}/{expected_students} öğrenci işleniyor...")
                        
                        page1 = pdf.pages[i]
                        page2 = pdf.pages[i + 1] if i + 1 < total_pages else None
                        
                        text1 = page1.extract_text() or ""
                        text2 = page2.extract_text() if page2 else ""
                        
                        student = self._parse_student(text1, text2)
                        if student and student.get('student_name'):
                            self.students.append(student)
                    except Exception as e:
                        logger.error(f"Sayfa {i} parse hatası: {e}")
                        continue
                
                logger.info(f"PDF parse tamamlandı: {len(self.students)} öğrenci bulundu")
                        
        except Exception as e:
            logger.error(f"PDF okuma hatası: {e}")
            raise e
            
        return self.students
    
    def _parse_student(self, text1: str, text2: str) -> Optional[Dict]:
        """Tek bir öğrencinin verilerini parse et"""
        student = {
            'student_name': None,
            'class_name': None,
            'student_no': None,
            'grade': 8,
            'lgs_score': None,
            'percentile': None,
            'total_questions': None,
            'total_correct': None,
            'total_wrong': None,
            'total_blank': None,
            'total_net': None,
            'success_rate': None,
            'ranks': {},
            'subjects': {},
            'answers': []
        }
        
        lines = text1.split('\n')
        for i, line in enumerate(lines):
            if 'SONUÇ BELGESİ' in line:
                continue
            class_match = re.search(r'(\d/[A-Z])\s*-?\s*(\d+)', line)
            if class_match:
                student['class_name'] = class_match.group(1)
                student['student_no'] = class_match.group(2)
                try:
                    student['grade'] = int(class_match.group(1)[0])
                except:
                    student['grade'] = 8
                if i > 0:
                    prev_line = lines[i-1].strip()
                    if prev_line and 'SONUÇ' not in prev_line and 'SINIF' not in prev_line:
                        name = prev_line.strip()
                        if len(name) > 3 and not any(c.isdigit() for c in name[:3]):
                            student['student_name'] = name
                break
        
        if not student['student_name']:
            for line in lines[:10]:
                line = line.strip()
                if line and len(line) > 5 and line.isupper() and 'SINAV' not in line and 'SONUÇ' not in line and 'BELGESİ' not in line:
                    if not any(c.isdigit() for c in line[:5]):
                        student['student_name'] = line
                        break
        
        lgs_match = re.search(r'(\d{3}[.,]\d{2,3})', text1)
        if lgs_match:
            score = lgs_match.group(1).replace(',', '.')
            student['lgs_score'] = float(score)
        
        percentile_match = re.search(r'Yüzdelik Dilim\s*\(%?\)?\s*(\d+[.,]\d+)', text1)
        if percentile_match:
            student['percentile'] = float(percentile_match.group(1).replace(',', '.'))
        
        stats_pattern = r'(\d{2,3})\s+(\d{1,3})\s+(\d{1,2})\s+(\d{1,2})\s+(\d{1,3}[.,]\d{1,2})'
        stats_matches = re.findall(stats_pattern, text1)
        if stats_matches:
            best_match = max(stats_matches, key=lambda x: int(x[0]))
            student['total_questions'] = int(best_match[0])
            student['total_correct'] = int(best_match[1])
            student['total_wrong'] = int(best_match[2])
            student['total_blank'] = int(best_match[3])
            student['success_rate'] = float(best_match[4].replace(',', '.'))
        
        self._parse_subject_answers(text1, student)
        
        if text2:
            self._parse_outcomes(text2, student)
        
        self._calculate_totals(student)
        
        return student
    
    def _calculate_totals(self, student: Dict):
        """Toplam istatistikleri hesapla - subjects zaten PDF değerleriyle doldurulmuşsa onları kullan"""
        total_correct = 0
        total_wrong = 0
        total_blank = 0
        total_questions = 0
        
        for subj, stats in student.get('subjects', {}).items():
            total_correct += stats.get('correct_count', 0)
            total_wrong += stats.get('wrong_count', 0)
            total_blank += stats.get('blank_count', 0)
            total_questions += stats.get('question_count', 0)
            
            answers_for_subj = [a for a in student['answers'] if a.get('subject') == subj]
            student['subjects'][subj]['student_answers'] = ''.join([
                a.get('student_answer', '_') if a.get('student_answer') else '_' 
                for a in sorted(answers_for_subj, key=lambda x: x.get('question_number', 0))
            ])
        
        total_net = total_correct - total_wrong
        
        student['total_correct'] = total_correct
        student['total_wrong'] = total_wrong
        student['total_blank'] = total_blank
        student['total_questions'] = total_questions
        student['total_net'] = round(total_net, 2)
        
        if total_questions > 0:
            student['success_rate'] = round((total_correct / total_questions) * 100, 2)
    
    def _parse_subject_stats_from_boxes(self, text: str, student: Dict):
        """
        PDF'deki ders istatistik kutularından değerleri oku (fallback parser için).
        PDF 2 sütunlu yapıda: Türkçe → İnkılap → Din → İngilizce → Matematik → Fen
        """
        grade = student.get('grade', 8)
        
        if grade in [5, 6, 7]:
            pdf_order = ['turkce', 'sosyal', 'din', 'ingilizce', 'matematik', 'fen']
        else:
            pdf_order = ['turkce', 'inkilap', 'din', 'ingilizce', 'matematik', 'fen']
        
        box_pattern = r'(20|10|15)\s+(\d{1,2})\s+(\d{1,2})\s+(\d{1,2})\s+(\d{1,2}[.,]\d{2})'
        box_matches = re.findall(box_pattern, text)
        
        pdf_stats = {}
        
        if len(box_matches) >= 6:
            for i, match in enumerate(box_matches[:6]):
                if i < len(pdf_order):
                    subject = pdf_order[i]
                    pdf_stats[subject] = {
                        'question_count': int(match[0]),
                        'correct_count': int(match[1]),
                        'wrong_count': int(match[2]),
                        'blank_count': int(match[3]),
                        'net_score': float(match[4].replace(',', '.'))
                    }
                    logger.info(f"PDF Stats {subject}: {match[1]}D, {match[2]}Y, {match[3]}B")
        
        return pdf_stats
    
    def _parse_subject_answers(self, text: str, student: Dict):
        """Ders cevaplarını parse et - 2 sütunlu PDF yapısını destekler"""
        grade = student.get('grade', 8)
        if grade in [5, 6, 7]:
            subjects_order = ['turkce', 'ingilizce', 'sosyal', 'matematik', 'din', 'fen']
            question_counts = [20, 10, 10, 20, 10, 20]
        else:
            subjects_order = ['turkce', 'ingilizce', 'inkilap', 'matematik', 'din', 'fen']
            question_counts = [20, 10, 10, 20, 10, 20]
        
        pdf_stats = self._parse_subject_stats_from_boxes(text, student)
        
        lines = text.split('\n')
        correct_lines = []
        student_lines = []
        
        for line in lines:
            if 'Doğ. Cevaplar' in line:
                correct_lines.append(line)
            elif 'Öğr. Cevaplar' in line:
                student_lines.append(line)
        
        correct_matches = []
        student_matches = []
        
        for line in correct_lines:
            parts = re.split(r'Doğ\.\s*Cevaplar\s*', line)
            for part in parts:
                clean = ''.join([c for c in part.upper() if c in 'ABCD'])
                if clean:
                    correct_matches.append(clean)
        
        for line in student_lines:
            parts = re.split(r'Öğr\.\s*Cevaplar\s*', line)
            for part in parts:
                if part.strip():
                    student_matches.append(part.strip())
        
        matched_subjects = subjects_order[:len(correct_matches)]
        
        logger.info(f"=== DEBUG CEVAP PARSE ===")
        logger.info(f"Doğru cevap eşleşmeleri ({len(correct_matches)}): {correct_matches}")
        logger.info(f"Öğrenci cevap eşleşmeleri ({len(student_matches)}): {[s[:20]+'...' for s in student_matches]}")
        logger.info(f"Eşleşen dersler: {matched_subjects}, Cevap sayıları: {[len(c) for c in correct_matches]}")
        
        for i, (correct, stud) in enumerate(zip(correct_matches, student_matches)):
            if i < len(matched_subjects):
                subject = matched_subjects[i]
                
                correct_answers = ''.join(correct.upper().split())
                expected_count = len(correct_answers)
                student_answers = stud.upper()
                
                # Debug: Tam string'i logla
                logger.info(f"DEBUG {subject}: Raw repr: {repr(stud[:expected_count+10])}")
                
                student_answers_list = []
                for c in stud:
                    c_upper = c.upper()
                    if c_upper in 'ABCD':
                        student_answers_list.append(c_upper)
                    elif c in ' -xX*.–—_\u2013\u2014\u00A0' or not c.isalnum():
                        student_answers_list.append('')
                
                # Fazla karakterleri kırp (soru sayısından fazla olamaz)
                if len(student_answers_list) > expected_count:
                    student_answers_list = student_answers_list[:expected_count]
                
                while len(student_answers_list) < expected_count:
                    student_answers_list.append('')
                
                logger.info(f"DEBUG {subject}: Parsed ({len(student_answers_list)}): {''.join([a if a else '_' for a in student_answers_list])}")
                logger.info(f"Ders {subject}: Doğru={len(correct_answers)}, Öğrenci={len(student_answers_list)}")
                
                correct_count = 0
                wrong_count = 0
                blank_count = 0
                
                for j, (ca, sa) in enumerate(zip(correct_answers, student_answers_list[:len(correct_answers)])):
                    if not sa or sa == '' or sa == ' ':
                        blank_count += 1
                        is_blank = True
                        is_correct = False
                    elif sa == ca:
                        correct_count += 1
                        is_blank = False
                        is_correct = True
                    else:
                        wrong_count += 1
                        is_blank = False
                        is_correct = False
                    
                    student['answers'].append({
                        'subject': subject,
                        'question_number': j + 1,
                        'correct_answer': ca,
                        'student_answer': sa if sa else '',
                        'is_correct': is_correct,
                        'is_blank': is_blank
                    })
                
                net = correct_count - wrong_count
                
                if subject in pdf_stats:
                    pdf_correct = pdf_stats[subject]['correct_count']
                    pdf_wrong = pdf_stats[subject]['wrong_count']
                    pdf_blank = pdf_stats[subject]['blank_count']
                    
                    if pdf_correct != correct_count or pdf_wrong != wrong_count or pdf_blank != blank_count:
                        logger.info(f"Fallback {subject}: PDF değerleri kullanılıyor: {pdf_correct}D/{pdf_wrong}Y/{pdf_blank}B (hesaplanan: {correct_count}D/{wrong_count}Y/{blank_count}B)")
                        correct_count = pdf_correct
                        wrong_count = pdf_wrong
                        blank_count = pdf_blank
                        net = correct_count - wrong_count
                
                student['subjects'][subject] = {
                    'question_count': len(correct_answers),
                    'correct_count': correct_count,
                    'wrong_count': wrong_count,
                    'blank_count': blank_count,
                    'net_score': round(net, 2),
                    'success_rate': round((correct_count / len(correct_answers)) * 100, 2) if correct_answers else 0,
                    'correct_answers': correct_answers,
                    'student_answers': ''.join([a if a else '_' for a in student_answers_list[:len(correct_answers)]])
                }
    
    def _parse_outcomes(self, text: str, student: Dict):
        """Kazanımları parse et - geliştirilmiş boş cevap algılama"""
        outcome_pattern = r'(\d+)\s+\ufeff?([A-Za-zİĞÜŞÖÇığüşöç\.]+[\.\d]+\.?\d*)\s*(.+?)([A-D])\s+([A-Da-d\-])\s*([+-]?)'
        matches = re.findall(outcome_pattern, text)
        
        blank_pattern = r'(\d+)\s+\ufeff?([A-Za-zİĞÜŞÖÇığüşöç\.]+[\.\d]+\.?\d*)\s*(.+?)([A-D])\s+[-\s]*$'
        blank_matches = re.findall(blank_pattern, text, re.MULTILINE)
        
        all_questions = {}
        
        for match in matches:
            try:
                question_no = int(match[0])
                code = match[1].strip()
                description = match[2].strip()[:100]
                correct = match[3].upper()
                student_ans = match[4].strip().upper() if match[4].strip() else ''
                
                if student_ans == '-':
                    student_ans = ''
                
                code_upper = code.upper()
                subject = None
                if code_upper.startswith('T.') or code_upper.startswith('T.S.'):
                    subject = 'turkce'
                elif code_upper.startswith('M.') or code_upper.startswith('MAT.'):
                    subject = 'matematik'
                elif code_upper.startswith('F.') or code_upper.startswith('FB.'):
                    subject = 'fen'
                elif code_upper.startswith('D.') or code_upper.startswith('DKAB.'):
                    subject = 'din'
                elif code_upper.startswith('E.'):
                    subject = 'ingilizce'
                elif code_upper.startswith('İTA') or code_upper.startswith('ITA'):
                    subject = 'inkilap'
                elif code_upper.startswith('SB.') or code_upper.startswith('S.'):
                    subject = 'sosyal'
                
                if subject:
                    key = f"{subject}_{question_no}"
                    all_questions[key] = {
                        'question_no': question_no,
                        'code': code,
                        'description': description,
                        'correct': correct,
                        'student_ans': student_ans,
                        'subject': subject,
                        'is_blank': student_ans == ''
                    }
            except (ValueError, IndexError):
                continue
        
        for match in blank_matches:
            try:
                question_no = int(match[0])
                code = match[1].strip()
                description = match[2].strip()[:100]
                correct = match[3].upper()
                
                code_upper = code.upper()
                subject = None
                if code_upper.startswith('T.') or code_upper.startswith('T.S.'):
                    subject = 'turkce'
                elif code_upper.startswith('M.') or code_upper.startswith('MAT.'):
                    subject = 'matematik'
                elif code_upper.startswith('F.') or code_upper.startswith('FB.'):
                    subject = 'fen'
                elif code_upper.startswith('D.') or code_upper.startswith('DKAB.'):
                    subject = 'din'
                elif code_upper.startswith('E.'):
                    subject = 'ingilizce'
                elif code_upper.startswith('İTA') or code_upper.startswith('ITA'):
                    subject = 'inkilap'
                elif code_upper.startswith('SB.') or code_upper.startswith('S.'):
                    subject = 'sosyal'
                
                if subject:
                    key = f"{subject}_{question_no}"
                    if key not in all_questions:
                        all_questions[key] = {
                            'question_no': question_no,
                            'code': code,
                            'description': description,
                            'correct': correct,
                            'student_ans': '',
                            'subject': subject,
                            'is_blank': True
                        }
                        logger.info(f"Boş cevap tespit edildi: {subject} S{question_no}")
            except (ValueError, IndexError):
                continue
        
        for key, data in all_questions.items():
            subject = data['subject']
            question_no = data['question_no']
            
            for ans in student['answers']:
                if ans['subject'] == subject and ans['question_number'] == question_no:
                    ans['outcome_code'] = data['code']
                    ans['outcome_text'] = data['description']
                    ans['correct_answer'] = data['correct']
                    ans['student_answer'] = data['student_ans']
                    ans['is_blank'] = data['is_blank']
                    ans['is_correct'] = (data['correct'] == data['student_ans']) if not data['is_blank'] else False
                    break


def parse_report_card_pdf(pdf_path: str) -> Tuple[List[Dict], Optional[str]]:
    """
    PDF karne dosyasını parse et - Docling öncelikli, pdfplumber fallback
    Returns: (students_list, error_message)
    """
    try:
        if DOCLING_AVAILABLE:
            logger.info("🚀 Docling ile PDF parse ediliyor...")
            parser = DoclingReportCardParser(pdf_path)
        else:
            logger.info("📄 pdfplumber ile PDF parse ediliyor...")
            parser = ReportCardParser(pdf_path)
        
        students = parser.parse()
        return students, None
    except Exception as e:
        logger.error(f"PDF parse hatası: {e}")
        return [], str(e)
