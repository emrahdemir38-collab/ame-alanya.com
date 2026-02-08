"""
Görsel Tabanlı Sınav Sonuç Belgesi Parser
Gemini AI Vision kullanarak sınav sonuç görsellerinden veri çıkarır
PDF'leri görüntüye çevirip okuyabilir
"""
import os
import re
import base64
import json
import logging
import io
from typing import Dict, List, Optional, Any
from datetime import datetime

from google import genai
from google.genai import types
from pdf2image import convert_from_bytes
from PIL import Image

logger = logging.getLogger(__name__)

AI_INTEGRATIONS_GEMINI_API_KEY = os.environ.get("AI_INTEGRATIONS_GEMINI_API_KEY")
AI_INTEGRATIONS_GEMINI_BASE_URL = os.environ.get("AI_INTEGRATIONS_GEMINI_BASE_URL")

client = None
if AI_INTEGRATIONS_GEMINI_API_KEY and AI_INTEGRATIONS_GEMINI_BASE_URL:
    try:
        client = genai.Client(
            api_key=AI_INTEGRATIONS_GEMINI_API_KEY,
            http_options={
                'api_version': '',
                'base_url': AI_INTEGRATIONS_GEMINI_BASE_URL   
            }
        )
        logger.info("Gemini AI client basariyla yapilandirildi")
    except Exception as e:
        logger.error(f"Gemini AI client yapilandirma hatasi: {e}")
        client = None
else:
    logger.warning("Gemini API anahtarlari eksik - gorsel analiz devre disi")

class ImageReportParser:
    """Görsel tabanlı sınav sonuç belgesi parser'ı"""
    
    SUBJECT_MAP = {
        'turkce': 'Türkçe',
        'matematik': 'Matematik',
        'fen': 'Fen Bilimleri',
        'sosyal': 'Sosyal Bilgiler',
        'ingilizce': 'İngilizce',
        'inkilap': 'İnkılap Tarihi',
        'din': 'Din Kültürü'
    }
    
    def __init__(self):
        self.model = "gemini-2.5-flash"
    
    def parse_pdf(self, pdf_data: bytes, first_page_only: bool = True) -> Dict:
        """PDF dosyasını görüntüye çevirip Gemini ile oku"""
        try:
            logger.info(f"PDF dönüştürme başlıyor, boyut: {len(pdf_data)} bytes")
            if first_page_only:
                pages = convert_from_bytes(pdf_data, dpi=200, first_page=1, last_page=1)
            else:
                pages = convert_from_bytes(pdf_data, dpi=200)
            logger.info(f"PDF dönüştürme sonucu: {len(pages)} sayfa")
            
            if not pages:
                return {'success': False, 'error': 'PDF sayfasi okunamadi'}
            
            img_byte_arr = io.BytesIO()
            pages[0].save(img_byte_arr, format='PNG', quality=95)
            img_byte_arr.seek(0)
            image_data = img_byte_arr.read()
            
            logger.info(f"PDF goruntiye cevirildi: {len(image_data)} bytes")
            
            return self.parse_image(image_data, 'image/png')
            
        except Exception as e:
            logger.error(f"PDF goruntiye cevirme hatasi: {e}")
            return {'success': False, 'error': f'PDF goruntiye cevirme hatasi: {str(e)}'}
    
    def parse_image(self, image_data: bytes, mime_type: str = "image/png") -> Dict:
        """Görsel dosyasından sınav sonuçlarını parse et"""
        if client is None:
            return {'success': False, 'error': 'Gemini AI yapilandirmasi eksik. Lutfen sistem yoneticisine basvurun.'}
        
        try:
            prompt = self._create_extraction_prompt()
            
            response = client.models.generate_content(
                model=self.model,
                contents=[
                    prompt,
                    types.Part(
                        inline_data=types.Blob(
                            mime_type=mime_type,
                            data=image_data
                        )
                    )
                ],
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )
            
            result_text = response.text or "{}"
            logger.info(f"Gemini response: {result_text[:500]}...")
            
            parsed_data = json.loads(result_text)
            return self._process_parsed_data(parsed_data)
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse hatası: {e}")
            return {'success': False, 'error': f'JSON parse hatası: {str(e)}'}
        except Exception as e:
            logger.error(f"Görsel parse hatası: {e}")
            return {'success': False, 'error': str(e)}
    
    def _create_extraction_prompt(self) -> str:
        """Veri çıkarma için prompt oluştur"""
        return """Bu Türk ortaokul sınav sonuç belgesi görselini analiz et ve JSON formatında veri çıkar.

ÖNEMLİ: Tüm verileri tam ve doğru olarak çıkar. Öğrenci cevaplarındaki boşlukları "_" (alt çizgi) olarak işaretle.

Çıkarılacak veriler:
1. Öğrenci bilgileri: Ad Soyad, Sınıf (örn: 8/A), Öğrenci No
2. Sınav bilgileri: Sınav adı (örn: "1. TÜRKİYE GENELİ SINAV")
3. Yüzdelik dilim bilgisi (varsa): Türkiye sıralaması, yüzdelik dilim
4. Genel istatistikler: Toplam soru, doğru, yanlış, boş, net, puan, başarı yüzdesi
5. Her ders için:
   - Ders adı (turkce, matematik, fen, ingilizce, inkilap, din, sosyal)
   - Soru sayısı, doğru, yanlış, boş, net
   - Doğru cevap anahtarı dizisi (örn: "BDCDADBCDDABADBACBCB")
   - Öğrenci cevapları dizisi (boşlar için "_" kullan, örn: "BD_DADB_D_ABADB__BCB")

JSON formatı:
{
  "student": {
    "name": "AD SOYAD",
    "class_name": "8/A",
    "student_no": "433"
  },
  "exam": {
    "name": "1. TÜRKİYE GENELİ SINAV",
    "date": "2024"
  },
  "ranking": {
    "turkey_rank": 12500,
    "percentile": 85.5,
    "total_participants": 150000
  },
  "totals": {
    "question_count": 90,
    "correct_count": 67,
    "wrong_count": 11,
    "blank_count": 12,
    "net_score": 63.33,
    "total_score": 392.116,
    "success_rate": 78.42
  },
  "subjects": {
    "turkce": {
      "question_count": 20,
      "correct_count": 17,
      "wrong_count": 3,
      "blank_count": 0,
      "net_score": 16.00,
      "correct_answers": "BDCDADBCDDABADBACBCB",
      "student_answers": "BbCDADBCDbABbDBAcBCB"
    },
    "ingilizce": {...},
    "inkilap": {...},
    "matematik": {...},
    "din": {...},
    "fen": {...}
  }
}

KURALLAR:
- Cevaplardaki küçük harfler yanlış cevabı gösterir, büyük harfe çevir
- Boş cevapları "_" ile göster
- Tüm sayıları doğru oku
- Sınıf formatı: "8/A" veya "5/B" gibi olmalı
- Ders isimlerini İngilizce olarak yaz: turkce, matematik, fen, ingilizce, inkilap, din, sosyal"""

    def _process_parsed_data(self, data: Dict) -> Dict:
        """Parse edilen veriyi işle ve doğrula"""
        try:
            student_info = data.get('student', {})
            exam_info = data.get('exam', {})
            totals = data.get('totals', {})
            subjects = data.get('subjects', {})
            ranking = data.get('ranking', {})
            
            student = {
                'name': student_info.get('name', 'Bilinmeyen Öğrenci'),
                'class_name': student_info.get('class_name', '8/A'),
                'student_no': student_info.get('student_no', ''),
                'grade': self._extract_grade(student_info.get('class_name', '8/A')),
                'exam_name': exam_info.get('name', 'Sınav'),
                'exam_date': exam_info.get('date', datetime.now().strftime('%Y-%m-%d')),
                'subjects': {},
                'answers': [],
                'ranking': {
                    'turkey_rank': ranking.get('turkey_rank'),
                    'percentile': ranking.get('percentile'),
                    'total_participants': ranking.get('total_participants')
                },
                'totals': {
                    'question_count': totals.get('question_count', 0),
                    'correct_count': totals.get('correct_count', 0),
                    'wrong_count': totals.get('wrong_count', 0),
                    'blank_count': totals.get('blank_count', 0),
                    'net_score': totals.get('net_score', 0),
                    'total_score': totals.get('total_score', 0),
                    'success_rate': totals.get('success_rate', 0)
                }
            }
            
            for subject_key, subject_data in subjects.items():
                subject_key_lower = subject_key.lower()
                
                correct_answers = subject_data.get('correct_answers', '')
                student_answers = subject_data.get('student_answers', '')
                
                correct_answers = ''.join([c.upper() for c in correct_answers if c.upper() in 'ABCD'])
                
                student_answers_list = []
                for c in student_answers:
                    if c.upper() in 'ABCD':
                        student_answers_list.append(c.upper())
                    elif c in '_- \t':
                        student_answers_list.append('')
                    else:
                        student_answers_list.append('')
                
                question_count = subject_data.get('question_count', len(correct_answers))
                
                while len(student_answers_list) < question_count:
                    student_answers_list.append('')
                student_answers_list = student_answers_list[:question_count]
                
                correct_count = 0
                wrong_count = 0
                blank_count = 0
                
                for i in range(question_count):
                    ca = correct_answers[i] if i < len(correct_answers) else ''
                    sa = student_answers_list[i] if i < len(student_answers_list) else ''
                    
                    if not sa:
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
                        'subject': subject_key_lower,
                        'question_number': i + 1,
                        'correct_answer': ca,
                        'student_answer': sa,
                        'is_correct': is_correct,
                        'is_blank': is_blank
                    })
                
                pdf_correct = subject_data.get('correct_count', correct_count)
                pdf_wrong = subject_data.get('wrong_count', wrong_count)
                pdf_blank = subject_data.get('blank_count', blank_count)
                
                subject_answers = []
                for i in range(question_count):
                    ca = correct_answers[i] if i < len(correct_answers) else ''
                    sa = student_answers_list[i] if i < len(student_answers_list) else ''
                    
                    if not sa:
                        status = 'blank'
                    elif sa == ca:
                        status = 'correct'
                    else:
                        status = 'wrong'
                    
                    subject_answers.append({
                        'question_number': i + 1,
                        'correct_answer': ca,
                        'student_answer': sa,
                        'status': status
                    })
                
                student['subjects'][subject_key_lower] = {
                    'question_count': question_count,
                    'correct_count': pdf_correct,
                    'wrong_count': pdf_wrong,
                    'blank_count': pdf_blank,
                    'net_score': subject_data.get('net_score', round(pdf_correct - pdf_wrong/4, 2)),
                    'success_rate': round((pdf_correct / question_count) * 100, 2) if question_count else 0,
                    'correct_answers': correct_answers,
                    'student_answers': ''.join([a if a else '_' for a in student_answers_list]),
                    'answers': subject_answers
                }
            
            return {
                'success': True,
                'students': [student],
                'exam_info': {
                    'name': exam_info.get('name', 'Sınav'),
                    'date': exam_info.get('date', ''),
                    'student_count': 1
                }
            }
            
        except Exception as e:
            logger.error(f"Veri işleme hatası: {e}")
            return {'success': False, 'error': str(e)}
    
    def _extract_grade(self, class_name: str) -> int:
        """Sınıf adından sınıf seviyesini çıkar"""
        match = re.match(r'(\d+)', class_name)
        if match:
            return int(match.group(1))
        return 8
    
    def parse_multiple_images(self, images: List[Dict]) -> Dict:
        """Birden fazla görseli işle"""
        all_students = []
        errors = []
        
        for i, img_data in enumerate(images):
            try:
                result = self.parse_image(
                    img_data['data'],
                    img_data.get('mime_type', 'image/png')
                )
                
                if result.get('success'):
                    all_students.extend(result.get('students', []))
                else:
                    errors.append(f"Görsel {i+1}: {result.get('error', 'Bilinmeyen hata')}")
            except Exception as e:
                errors.append(f"Görsel {i+1}: {str(e)}")
        
        return {
            'success': len(all_students) > 0,
            'students': all_students,
            'errors': errors,
            'exam_info': {
                'student_count': len(all_students)
            }
        }
