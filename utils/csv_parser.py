"""
CSV/Excel Tabanlı Sınav Sonuç Parser
FMT'den dönüştürülmüş düzenli CSV/Excel dosyalarını okur
"""
import io
import csv
import logging
from typing import Dict, List, Optional, Tuple
import openpyxl

logger = logging.getLogger(__name__)

class CSVExcelParser:
    """CSV ve Excel dosyalarından sınav sonuçlarını parse eder"""
    
    SUBJECT_ORDER_SESSION2 = ['turkce', 'sosyal', 'din', 'ingilizce']
    SUBJECT_ORDER_SESSION2_8 = ['turkce', 'inkilap', 'din', 'ingilizce']
    SUBJECT_ORDER_SESSION1 = ['matematik', 'fen']
    
    SUBJECT_ORDER_FULL = ['turkce', 'sosyal', 'din', 'ingilizce', 'matematik', 'fen']
    SUBJECT_ORDER_FULL_8 = ['turkce', 'inkilap', 'din', 'ingilizce', 'matematik', 'fen']
    
    SUBJECT_QUESTIONS_56 = {
        'turkce': 15,
        'sosyal': 10,
        'din': 10,
        'ingilizce': 10,
        'matematik': 15,
        'fen': 15
    }
    
    SUBJECT_QUESTIONS_7 = {
        'turkce': 20,
        'sosyal': 10,
        'din': 10,
        'ingilizce': 10,
        'matematik': 20,
        'fen': 20
    }
    
    SUBJECT_QUESTIONS_8 = {
        'turkce': 20,
        'inkilap': 10,
        'din': 10,
        'ingilizce': 10,
        'matematik': 20,
        'fen': 20
    }
    
    SUBJECT_LABELS = {
        'turkce': 'Türkçe',
        'sosyal': 'Sosyal Bilgiler',
        'din': 'Din Kültürü',
        'ingilizce': 'İngilizce',
        'matematik': 'Matematik',
        'fen': 'Fen Bilimleri',
        'inkilap': 'İnkılap Tarihi'
    }
    
    def _get_subject_questions(self, grade: int) -> Dict:
        """Sınıf seviyesine göre soru sayılarını döndür"""
        if grade == 8:
            return self.SUBJECT_QUESTIONS_8
        elif grade == 7:
            return self.SUBJECT_QUESTIONS_7
        else:
            return self.SUBJECT_QUESTIONS_56
    
    def _get_subject_order(self, grade: int, session: str) -> List[str]:
        """Sınıf seviyesine göre ders sırasını döndür"""
        if session == '2':
            return self.SUBJECT_ORDER_SESSION2_8 if grade == 8 else self.SUBJECT_ORDER_SESSION2
        elif session == '1':
            return self.SUBJECT_ORDER_SESSION1
        else:
            return self.SUBJECT_ORDER_FULL_8 if grade == 8 else self.SUBJECT_ORDER_FULL
    
    def __init__(self, answer_key: Dict = None, fetch_student_names: bool = True):
        self.answer_key = answer_key or {}
        self.fetch_student_names = fetch_student_names
        self.student_name_cache = {}
    
    def parse_csv(self, file_data: bytes, delimiter: str = ';') -> Dict:
        """CSV dosyasını parse et - başlıksız format"""
        try:
            content = None
            encodings = ['utf-8-sig', 'utf-8', 'windows-1254', 'iso-8859-9', 'latin-1']
            for encoding in encodings:
                try:
                    content = file_data.decode(encoding)
                    if 'Ä' not in content and 'Ã' not in content:
                        break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                content = file_data.decode('latin-1')
            
            lines = content.strip().split('\n')
            if not lines:
                return {'success': False, 'error': 'CSV dosyası boş'}
            
            return self._process_headerless_rows(lines, delimiter)
            
        except Exception as e:
            logger.error(f"CSV parse hatası: {e}")
            return {'success': False, 'error': f'CSV parse hatası: {str(e)}'}
    
    def parse_excel(self, file_data: bytes) -> Dict:
        """Excel dosyasını parse et"""
        try:
            wb = openpyxl.load_workbook(io.BytesIO(file_data), data_only=True)
            ws = wb.active
            
            rows = list(ws.iter_rows(values_only=True))
            if not rows:
                return {'success': False, 'error': 'Excel dosyası boş'}
            
            lines = []
            for row in rows:
                line = ';'.join([str(cell) if cell is not None else '' for cell in row])
                lines.append(line)
            
            return self._process_headerless_rows(lines, ';')
            
        except Exception as e:
            logger.error(f"Excel parse hatası: {e}")
            return {'success': False, 'error': f'Excel parse hatası: {str(e)}'}
    
    def _process_headerless_rows(self, lines: List[str], delimiter: str) -> Dict:
        """Başlıksız satırları işle
        Format: Kurum;OgrenciNo;Oturum;Kitapcik;AdSoyad;Sinif;Ders1;Ders2;Ders3;Ders4;[Ders5;Ders6]
        """
        students_by_no = {}
        errors = []
        
        for idx, line in enumerate(lines):
            try:
                parts = line.strip().split(delimiter)
                if len(parts) < 7:
                    continue
                
                kurum = parts[0].strip()
                student_no = parts[1].strip()
                oturum = parts[2].strip()
                kitapcik = parts[3].strip().upper()
                ad_soyad = parts[4].strip().upper()
                sinif = parts[5].strip()
                
                if not student_no or student_no == '' or not ad_soyad:
                    continue
                
                key = f"{student_no}"
                
                if key not in students_by_no:
                    students_by_no[key] = {
                        'name': ad_soyad,
                        'class_name': sinif,
                        'student_no': student_no,
                        'grade': self._extract_grade(sinif),
                        'booklet_type': kitapcik if kitapcik in ['A', 'B'] else None,
                        'subjects': {},
                        'sessions': {},
                        'totals': {
                            'question_count': 0,
                            'correct_count': 0,
                            'wrong_count': 0,
                            'blank_count': 0,
                            'net_score': 0,
                            'success_rate': 0
                        }
                    }
                
                student = students_by_no[key]
                
                if kitapcik in ['A', 'B'] and not student['booklet_type']:
                    student['booklet_type'] = kitapcik
                
                grade = student['grade']
                subjects = self._get_subject_order(grade, oturum)
                
                if oturum == '2':
                    answers_list = parts[6:10]
                elif oturum == '1':
                    answers_list = [parts[10] if len(parts) > 10 else '', 
                                   parts[11] if len(parts) > 11 else '']
                else:
                    answers_list = parts[6:12]
                
                session_booklet = kitapcik if kitapcik in ['A', 'B'] else 'A'
                
                student['sessions'][oturum] = {
                    'booklet': session_booklet,
                    'subjects': []
                }
                
                if 'SIMA' in ad_soyad or 'SİMA' in ad_soyad:
                    logger.info(f"DEBUG SİMA - Oturum: {oturum}, Kitapçık: {session_booklet}")
                    logger.info(f"DEBUG SİMA - Dersler: {subjects}")
                    logger.info(f"DEBUG SİMA - Cevaplar: {answers_list}")
                
                for i, subject_key in enumerate(subjects):
                    if i < len(answers_list):
                        # KRITIK: strip() değil rstrip() kullan - baştaki boşluklar boş soru demek!
                        answers = answers_list[i].rstrip()
                        if answers:
                            if 'SIMA' in ad_soyad or 'SİMA' in ad_soyad:
                                logger.info(f"DEBUG SİMA - {subject_key}: öğrenci={answers[:20]}, kitapçık={session_booklet}")
                            
                            subject_data = self._process_subject(
                                subject_key, 
                                answers, 
                                session_booklet,
                                grade
                            )
                            if subject_data:
                                student['subjects'][subject_key] = subject_data
                                student['sessions'][oturum]['subjects'].append(subject_key)
                                
                                if 'SIMA' in ad_soyad or 'SİMA' in ad_soyad:
                                    logger.info(f"DEBUG SİMA - {subject_key}: doğru={subject_data['correct_count']}, yanlış={subject_data['wrong_count']}")
                    
            except Exception as e:
                errors.append(f"Satır {idx + 1}: {str(e)}")
                logger.error(f"Satır işleme hatası: {e}")
        
        students = []
        for key, student in students_by_no.items():
            student['totals'] = {
                'question_count': 0,
                'correct_count': 0,
                'wrong_count': 0,
                'blank_count': 0,
                'net_score': 0,
                'success_rate': 0
            }
            
            for subject_data in student['subjects'].values():
                student['totals']['question_count'] += subject_data['question_count']
                student['totals']['correct_count'] += subject_data['correct_count']
                student['totals']['wrong_count'] += subject_data['wrong_count']
                student['totals']['blank_count'] += subject_data['blank_count']
                student['totals']['net_score'] += subject_data['net_score']
            
            if student['totals']['question_count'] > 0:
                student['totals']['success_rate'] = round(
                    (student['totals']['correct_count'] / student['totals']['question_count']) * 100, 2
                )
            
            if student['subjects']:
                students.append(student)
        
        if not students:
            return {'success': False, 'error': 'Hiç öğrenci verisi bulunamadı'}
        
        return {
            'success': True,
            'students': students,
            'student_count': len(students),
            'errors': errors if errors else None
        }
    
    def _process_subject(self, subject_key: str, answers: str, booklet_type: str = 'A', grade: int = 5) -> Optional[Dict]:
        """Ders cevaplarını işle - kitapçık tipine göre cevap anahtarı seç"""
        if not answers or answers.strip() == '':
            return None
        
        # KRITIK: strip() kullanma! Baştaki boşluklar "boş bırakılan soru" demek
        # Sadece sondaki boşlukları temizle
        answers = answers.rstrip().upper()
        # ABCD = geçerli cevap, * = hatalı işaretleme (yanlış sayılır), diğerleri = boş
        answers = ''.join([c if c in 'ABCD*' else '_' for c in answers])
        
        subject_questions = self._get_subject_questions(grade)
        q_count = subject_questions.get(subject_key, len(answers))
        
        if len(answers) < q_count:
            answers = answers + '_' * (q_count - len(answers))
        answers = answers[:q_count]
        
        booklet_key = self.answer_key.get(booklet_type, {})
        subject_ak = booklet_key.get(subject_key, {})
        
        if isinstance(subject_ak, dict):
            correct_key = subject_ak.get('answers', '')
            questions_data = subject_ak.get('questions', [])
        else:
            correct_key = subject_ak
            questions_data = []
        
        if not correct_key and booklet_type == 'B':
            fallback_key = self.answer_key.get('A', {}).get(subject_key, {})
            if isinstance(fallback_key, dict):
                correct_key = fallback_key.get('answers', '')
                questions_data = fallback_key.get('questions', [])
            else:
                correct_key = fallback_key
        
        correct_count = 0
        wrong_count = 0
        blank_count = 0
        subject_answers = []
        
        for i, ans in enumerate(answers):
            correct_ans = correct_key[i].upper() if i < len(correct_key) else ''
            
            outcome = ''
            if i < len(questions_data):
                outcome = questions_data[i].get('outcome', '')
            
            if ans == '_' or ans == ' ' or ans == '':
                # Gerçek boş - hiç işaretlenmemiş
                status = 'blank'
                blank_count += 1
            elif ans == '*':
                # * işareti = hatalı işaretleme (birden fazla şık vb.) = YANLIŞ
                status = 'wrong'
                wrong_count += 1
            elif correct_ans and ans == correct_ans:
                status = 'correct'
                correct_count += 1
            elif correct_ans:
                status = 'wrong'
                wrong_count += 1
            else:
                status = 'unknown'
            
            subject_answers.append({
                'question_number': i + 1,
                'student_answer': ans if ans not in ['_', '*'] else '',
                'correct_answer': correct_ans,
                'status': status,
                'outcome': outcome
            })
        
        net_score = round(correct_count - (wrong_count / 4), 2)
        
        return {
            'subject_label': self.SUBJECT_LABELS.get(subject_key, subject_key),
            'question_count': q_count,
            'correct_count': correct_count,
            'wrong_count': wrong_count,
            'blank_count': blank_count,
            'net_score': net_score,
            'success_rate': round((correct_count / q_count) * 100, 2) if q_count else 0,
            'student_answers': answers.replace('_', '-'),
            'correct_answers': correct_key,
            'booklet_type': booklet_type,
            'answers': subject_answers
        }
    
    def _extract_grade(self, class_name: str) -> int:
        """Sınıf adından seviye çıkar"""
        if not class_name:
            return 5
        
        import re
        match = re.search(r'(\d+)', class_name)
        if match:
            return int(match.group(1))
        return 5
