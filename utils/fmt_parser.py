"""
FMT Dosya Parser - Optik Okuyucu Veri Dosyası
İki format desteklenir:

ESKİ FORMAT:
00768146       000321AAHMET EREN YILMAZ   5 BACA CC BADCADCC    DBBCBDACCA...
                ^^^^^ ^                   ^ ^
                ÖğrNo+O K                 S Ş  (O=oturum, K=kitapçık, S=sınıf, Ş=şube)

YENİ FORMAT:
00768146  00094 2 B BERİL ÇAKIROĞLU  5C CADCA ADBAACB D  AABCCABBCA...
          ^^^^^ ^ ^                  ^^
          ÖğrNo O K                  Sınıf/Şube

Her satırda HER İKİ OTURUM birlikte var!
SÖZEL: Türkçe(15) + Sosyal(10) + Din(10) + İngilizce(10) = 45 karakter
SAYISAL: Matematik(15) + Fen(15) = 30 karakter
"""
import re
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class FMTReportCardParser:
    """FMT dosyalarından sınav sonuçlarını parse eder"""
    
    SUBJECT_DISPLAY_NAMES = {
        'turkce': 'Türkçe',
        'ingilizce': 'İngilizce', 
        'sosyal': 'Sosyal Bilgiler',
        'inkilap': 'İnkılap Tarihi',
        'matematik': 'Matematik',
        'din': 'Din Kültürü',
        'fen': 'Fen Bilimleri'
    }
    
    GRADE_CONFIGS = {
        5: {
            'sozel_subjects': ['turkce', 'sosyal', 'din', 'ingilizce'],
            'sayisal_subjects': ['matematik', 'fen'],
            'question_counts': {'turkce': 15, 'sosyal': 10, 'din': 10, 'ingilizce': 10, 'matematik': 15, 'fen': 15},
            'sozel_order': ['turkce', 'sosyal', 'din', 'ingilizce'],
            'sayisal_order': ['matematik', 'fen'],
            'total_questions': 75
        },
        6: {
            'sozel_subjects': ['turkce', 'sosyal', 'din', 'ingilizce'],
            'sayisal_subjects': ['matematik', 'fen'],
            'question_counts': {'turkce': 15, 'sosyal': 10, 'din': 10, 'ingilizce': 10, 'matematik': 15, 'fen': 15},
            'sozel_order': ['turkce', 'sosyal', 'din', 'ingilizce'],
            'sayisal_order': ['matematik', 'fen'],
            'total_questions': 75
        },
        7: {
            'sozel_subjects': ['turkce', 'sosyal', 'din', 'ingilizce'],
            'sayisal_subjects': ['matematik', 'fen'],
            'question_counts': {'turkce': 20, 'sosyal': 10, 'din': 10, 'ingilizce': 10, 'matematik': 20, 'fen': 20},
            'sozel_order': ['turkce', 'sosyal', 'din', 'ingilizce'],
            'sayisal_order': ['matematik', 'fen'],
            'total_questions': 90
        },
        8: {
            'sozel_subjects': ['turkce', 'inkilap', 'din', 'ingilizce'],
            'sayisal_subjects': ['matematik', 'fen'],
            'question_counts': {'turkce': 20, 'inkilap': 10, 'din': 10, 'ingilizce': 10, 'matematik': 20, 'fen': 20},
            'sozel_order': ['turkce', 'inkilap', 'din', 'ingilizce'],
            'sayisal_order': ['matematik', 'fen'],
            'total_questions': 90
        }
    }
    
    ENCODINGS = ['iso-8859-9', 'cp1254', 'latin-1', 'cp1252', 'utf-8']
    
    def __init__(self, file_content: bytes = None, file_path: str = None, answer_key: Dict = None, answer_key_b: Dict = None):
        self.file_content = file_content
        self.file_path = file_path
        self.students = []
        self.text_content = None
        self.answer_key_a = answer_key or {}
        self.answer_key_b = answer_key_b or {}
        
    def _decode_content(self) -> str:
        """Dosya içeriğini decode et - Türkçe karakterler için"""
        content = self.file_content
        if self.file_path and not content:
            with open(self.file_path, 'rb') as f:
                content = f.read()
        
        for encoding in self.ENCODINGS:
            try:
                decoded = content.decode(encoding)
                return decoded
            except (UnicodeDecodeError, AttributeError):
                continue
        
        return content.decode('latin-1', errors='replace')
    
    def parse(self) -> List[Dict]:
        """FMT dosyasını parse et - her satırda 2 oturum birlikte"""
        self.text_content = self._decode_content()
        lines = self.text_content.strip().split('\n')
        
        logger.info(f"FMT parse başladı: {len(lines)} satır")
        
        temp_students = {}
        debug_count = 0
        
        for line_num, line in enumerate(lines):
            try:
                line = line.rstrip('\r\n')
                if len(line) < 50:
                    continue
                
                parsed = self._parse_line_new_format(line, debug_count < 5)
                if not parsed:
                    parsed = self._parse_line_old_format(line, debug_count < 5)
                
                if not parsed:
                    continue
                
                if debug_count < 5:
                    debug_count += 1
                
                student_no = parsed['student_no']
                if not student_no:
                    continue
                
                session_type = parsed.get('session_type')
                key = student_no
                
                if key not in temp_students:
                    temp_students[key] = {
                        'student_name': parsed['student_name'],
                        'student_no': student_no,
                        'class_name': parsed['class_name'],
                        'grade': parsed['grade'],
                        'booklet_type': parsed['booklet_type'],
                        'subjects': {},
                        'answers': []
                    }
                
                for subj, answers in parsed.get('parsed_subjects', {}).items():
                    if answers and answers.strip():
                        existing = temp_students[key]['subjects'].get(subj, {}).get('student_answers', '')
                        new_filled = len([c for c in answers if c in 'ABCDabcd'])
                        old_filled = len([c for c in existing if c in 'ABCDabcd'])
                        if new_filled > old_filled:
                            config = self.GRADE_CONFIGS.get(parsed['grade'], self.GRADE_CONFIGS[5])
                            q_count = config['question_counts'].get(subj, 10)
                            temp_students[key]['subjects'][subj] = {
                                'question_count': q_count,
                                'student_answers': answers[:q_count].replace(' ', '-').replace('*', '-'),
                                'is_graded': False
                            }
                
                if parsed.get('booklet_type') and parsed['booklet_type'] in ['A', 'B']:
                    temp_students[key]['booklet_type'] = parsed['booklet_type']
                
                if parsed.get('student_name') and len(parsed['student_name']) > len(temp_students[key].get('student_name', '')):
                    temp_students[key]['student_name'] = parsed['student_name']
                    
            except Exception as e:
                logger.debug(f"Satır {line_num + 1} parse hatası: {e}")
                continue
        
        for student in temp_students.values():
            grade = student.get('grade', 5)
            config = self.GRADE_CONFIGS.get(grade, self.GRADE_CONFIGS[5])
            
            for subj in config['sozel_subjects'] + config['sayisal_subjects']:
                if subj not in student['subjects']:
                    q_count = config['question_counts'].get(subj, 10)
                    student['subjects'][subj] = {
                        'question_count': q_count,
                        'student_answers': '-' * q_count,
                        'is_graded': False
                    }
        
        self.students = list(temp_students.values())
        logger.info(f"FMT parse tamamlandı: {len(self.students)} benzersiz öğrenci ({len(lines)} satırdan)")
        return self.students
    
    def _parse_line_old_format(self, line: str, debug: bool = False) -> Optional[Dict]:
        """
        ESKİ FORMAT:
        00768146       000321AAHMET EREN YILMAZ   5 BACA CC BADCADCC    DBBCBDACCA...
        
        Öğrenci no son hanesi: 1=sözel, 2=sayısal
        Her satırda HER İKİ OTURUM cevapları VAR (121 karakter)
        """
        if len(line) < 50:
            return None
        
        kurum_match = re.match(r'^(\d{6,8})\s+', line)
        if not kurum_match:
            return None
        
        pos = kurum_match.end()
        remaining = line[pos:]
        
        ogrenci_match = re.match(r'(\d{5,6})([AB])([A-ZĞÜŞİÖÇa-zğüşıöç][A-ZĞÜŞİÖÇa-zğüşıöç\s]{2,25})', remaining)
        
        session_type = None
        
        if ogrenci_match:
            raw_student_no = ogrenci_match.group(1)
            if len(raw_student_no) >= 2 and raw_student_no[-1] in '12':
                session_type = 'sozel' if raw_student_no[-1] == '1' else 'sayisal'
                student_no = raw_student_no[:-1].lstrip('0') or '0'
            else:
                student_no = raw_student_no.lstrip('0') or '0'
            booklet_type = ogrenci_match.group(2)
            student_name = self._clean_name(ogrenci_match.group(3).strip())
            remaining = remaining[ogrenci_match.end():]
        else:
            ogrenci_match2 = re.match(r'(\d{5,6})([AB]?)\s*', remaining)
            if not ogrenci_match2:
                return None
            raw_student_no = ogrenci_match2.group(1)
            if len(raw_student_no) >= 2 and raw_student_no[-1] in '12':
                session_type = 'sozel' if raw_student_no[-1] == '1' else 'sayisal'
                student_no = raw_student_no[:-1].lstrip('0') or '0'
            else:
                student_no = raw_student_no.lstrip('0') or '0'
            booklet_type = ogrenci_match2.group(2) if ogrenci_match2.group(2) else 'A'
            remaining = remaining[ogrenci_match2.end():]
            
            name_match = re.match(r'([A-ZĞÜŞİÖÇa-zğüşıöç][A-ZĞÜŞİÖÇa-zğüşıöç\s]{2,25})', remaining)
            if name_match:
                student_name = self._clean_name(name_match.group(1).strip())
                remaining = remaining[name_match.end():]
            else:
                student_name = ""
        
        grade_match = re.match(r'\s*([5-8])\s*([A-ZĞÜŞİÖÇ])?\s*', remaining)
        if grade_match:
            grade = int(grade_match.group(1))
            class_letter = grade_match.group(2).upper() if grade_match.group(2) else ''
            class_name = f"{grade}/{class_letter}" if class_letter else str(grade)
            remaining = remaining[grade_match.end():]
        else:
            grade = 5
            class_name = "5"
        
        leading_letter_match = re.match(r'^([A-D])\s{2,}', remaining)
        if leading_letter_match:
            remaining = remaining[leading_letter_match.end():]
        
        config = self.GRADE_CONFIGS.get(grade, self.GRADE_CONFIGS[5])
        
        all_answers = remaining.replace(' ', '-')
        all_answers = ''.join(c.upper() if c.upper() in 'ABCD' else '-' for c in all_answers)
        
        if debug:
            logger.info(f"DEBUG OLD: öğrenci={student_name}, sınıf={class_name}, oturum={session_type}, cevap_uzunluk={len(all_answers)}, cevaplar='{all_answers[:60]}...'")
        
        parsed_subjects = {}
        
        sozel_total = sum(config['question_counts'].get(s, 10) for s in config['sozel_order'])
        sayisal_total = sum(config['question_counts'].get(s, 15) for s in config['sayisal_order'])
        
        pos = 0
        for subj in config['sozel_order']:
            q_count = config['question_counts'].get(subj, 10)
            answers = all_answers[pos:pos+q_count] if pos < len(all_answers) else ''
            if len(answers) < q_count:
                answers = answers + '-' * (q_count - len(answers))
            parsed_subjects[subj] = answers
            pos += q_count
        
        for subj in config['sayisal_order']:
            q_count = config['question_counts'].get(subj, 15)
            answers = all_answers[pos:pos+q_count] if pos < len(all_answers) else ''
            if len(answers) < q_count:
                answers = answers + '-' * (q_count - len(answers))
            parsed_subjects[subj] = answers
            pos += q_count
        
        return {
            'student_name': student_name,
            'student_no': student_no,
            'class_name': class_name,
            'grade': grade,
            'booklet_type': booklet_type,
            'session_type': session_type,
            'parsed_subjects': parsed_subjects
        }
    
    def _parse_line_new_format(self, line: str, debug: bool = False) -> Optional[Dict]:
        """
        YENİ FORMAT:
        00768146  00094 2 B BERİL ÇAKIROĞLU  5C CADCA ADBAACB D  AABCCABBCA  BDBBBCBAB  DADDDCCBDA
        
        Alanlar:
        - Kurum kodu: 8 hane
        - Öğrenci no: 5 hane  
        - Oturum: 1 veya 2 (1=sözel form, 2=sayısal form - ama cevaplar ikisi de var)
        - Kitapçık: A veya B
        - İsim: değişken uzunluk
        - Sınıf: 5A, 5B, 5C vb.
        - SÖZEL CEVAPLAR: Türkçe(15) + Sosyal(10) + Din(10) + İngilizce(10) = 45 karakter
        - SAYISAL CEVAPLAR: Matematik(15) + Fen(15) = 30 karakter
        
        Toplam cevap: 75 karakter (boşluklar dahil)
        """
        if len(line) < 50:
            return None
        
        kurum_match = re.match(r'^(\d{6,8})\s+', line)
        if not kurum_match:
            return None
        
        pos = kurum_match.end()
        remaining = line[pos:]
        
        ogrenci_match = re.match(r'(\d{4,6})\s+(\d)\s+([AB])\s+', remaining)
        if not ogrenci_match:
            return None
        
        student_no = ogrenci_match.group(1).lstrip('0') or '0'
        session_form = ogrenci_match.group(2)
        booklet_type = ogrenci_match.group(3)
        remaining = remaining[ogrenci_match.end():]
        
        name_class_match = re.match(r'([A-ZĞÜŞİÖÇa-zğüşıöç][A-ZĞÜŞİÖÇa-zğüşıöç\s]+?)\s+([5-8])([A-Z])\s+', remaining)
        if not name_class_match:
            name_match = re.match(r'([A-ZĞÜŞİÖÇa-zğüşıöç][A-ZĞÜŞİÖÇa-zğüşıöç\s]+?)\s{2,}', remaining)
            if name_match:
                student_name = self._clean_name(name_match.group(1))
                remaining = remaining[name_match.end():]
                class_match = re.match(r'([5-8])([A-Z]?)\s*', remaining)
                if class_match:
                    grade = int(class_match.group(1))
                    class_letter = class_match.group(2) or ''
                    class_name = f"{grade}/{class_letter}" if class_letter else str(grade)
                    remaining = remaining[class_match.end():]
                else:
                    grade = 5
                    class_name = "5"
            else:
                return None
        else:
            student_name = self._clean_name(name_class_match.group(1))
            grade = int(name_class_match.group(2))
            class_letter = name_class_match.group(3)
            class_name = f"{grade}/{class_letter}"
            remaining = remaining[name_class_match.end():]
        
        config = self.GRADE_CONFIGS.get(grade, self.GRADE_CONFIGS[5])
        
        all_answers = ''.join(c if c in 'ABCDabcd ' else '' for c in remaining)
        all_answers = all_answers.replace(' ', '-')
        
        if debug:
            logger.info(f"DEBUG NEW: öğrenci={student_name}, sınıf={class_name}, cevap_uzunluk={len(all_answers)}, cevaplar='{all_answers[:80]}...'")
        
        parsed_subjects = {}
        
        pos = 0
        for subj in config['sozel_order']:
            q_count = config['question_counts'].get(subj, 10)
            answers = all_answers[pos:pos+q_count] if pos < len(all_answers) else ''
            if len(answers) < q_count:
                answers = answers + '-' * (q_count - len(answers))
            parsed_subjects[subj] = answers
            pos += q_count
        
        for subj in config['sayisal_order']:
            q_count = config['question_counts'].get(subj, 15)
            answers = all_answers[pos:pos+q_count] if pos < len(all_answers) else ''
            if len(answers) < q_count:
                answers = answers + '-' * (q_count - len(answers))
            parsed_subjects[subj] = answers
            pos += q_count
        
        return {
            'student_name': student_name,
            'student_no': student_no,
            'class_name': class_name,
            'grade': grade,
            'booklet_type': booklet_type,
            'session_type': None,
            'parsed_subjects': parsed_subjects
        }
    
    def _clean_name(self, name: str) -> str:
        """Türkçe karakter düzeltmeleri"""
        replacements = {
            'Ý': 'İ', 'Ð': 'Ğ', 'Þ': 'Ş', 
            'ý': 'ı', 'ð': 'ğ', 'þ': 'ş'
        }
        for old, new in replacements.items():
            name = name.replace(old, new)
        
        name = ' '.join(name.split())
        return name.strip()


def parse_fmt_files(file_contents: List[bytes]) -> List[Dict]:
    """Birden fazla FMT dosyasını parse et"""
    all_students = []
    
    for content in file_contents:
        parser = FMTReportCardParser(file_content=content)
        students = parser.parse()
        all_students.extend(students)
    
    logger.info(f"Toplam {len(all_students)} öğrenci parse edildi")
    return all_students
