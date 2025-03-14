import os
import sys
import time
import pandas as pd
from datetime import datetime
import re

def extract_date_info(filename):
    """
    파일명에서 연도, 월, 일 정보를 추출합니다.
    다양한 패턴을 확인하여 날짜 정보를 찾습니다.
    """
    pattern_8digits = r'(\d{4})(\d{2})(\d{2})'
    match = re.search(pattern_8digits, filename)
    if match:
        year, month, day = match.groups()
        try:
            year_int = int(year)
            month_int = int(month)
            day_int = int(day)
            if 1000 <= year_int <= 2100 and 1 <= month_int <= 12 and 1 <= day_int <= 31:
                return {
                    'year': year_int,
                    'month': month_int,
                    'day': day_int
                }
        except ValueError:
            pass
        
    pattern_year_monthday = r'(\d{4})-(\d{4})'
    match = re.search(pattern_year_monthday, filename)
    if match:
        year, monthday = match.groups()
        try:
            year_int = int(year)
            # 앞 두 자리는 월, 뒤 두 자리는 일
            if len(monthday) == 4:
                month_str = monthday[:2]
                day_str = monthday[2:]
                month_int = int(month_str)
                day_int = int(day_str)
                if 1000 <= year_int <= 2100 and 1 <= month_int <= 12 and 1 <= day_int <= 31:
                    return {
                        'year': year_int,
                        'month': month_int,
                        'day': day_int
                    }
        except ValueError:
            pass
        
    patterns = [
        r'pdfsinmun(\d{4})(\d{2})(\d{2})',  
        r'pdf(\d{4})(\d{2})',               
        r'pdf(\d{4})',                     
    ]
    
    for pattern in patterns:
        match = re.search(pattern, filename)
        if match:
            groups = match.groups()
            if len(groups) == 3:
                return {
                    'year': int(groups[0]),
                    'month': int(groups[1]),
                    'day': int(groups[2])
                }
            elif len(groups) == 2:
                return {
                    'year': int(groups[0]),
                    'month': int(groups[1]),
                    'day': None
                }
            elif len(groups) == 1:
                return {
                    'year': int(groups[0]),
                    'month': None,
                    'day': None
                }
    
    year_pattern = r'(19\d{2}|20\d{2})'
    match = re.search(year_pattern, filename)
    if match:
        try:
            year = int(match.group(1))
            return {
                'year': year,
                'month': None,
                'day': None
            }
        except ValueError:
            pass
    
    return {
        'year': None,
        'month': None,
        'day': None
    }

def find_pdf_files(root_dir):
    """
    PDF 파일만 탐색하고 정보를 수집하는 함수
    """
    file_info_list = []
    
    if not os.path.exists(root_dir):
        print(f"경로가 존재하지 않습니다: {root_dir}")
        return file_info_list
    
    total_files = 0
    processed_dirs = 0
    start_time = time.time()
    
    print(f"'{root_dir}' 경로에서 PDF 파일을 검색합니다...")
    
    # os.walk()를 사용해 모든 디렉토리와 파일을 재귀적으로 탐색
    for dirpath, dirnames, filenames in os.walk(root_dir):
        processed_dirs += 1
        
        dir_name = os.path.basename(dirpath)
        dir_date_info = extract_date_info(dir_name)
        
        for filename in filenames:
            _, extension = os.path.splitext(filename)
            if extension.lower() != '.pdf':
                continue
                
            file_date_info = extract_date_info(filename)
            full_path = os.path.join(dirpath, filename)
            relative_path = os.path.relpath(full_path, root_dir)
            
            print(f"탐색 중: {full_path}")
            
            file_info = {
                'filename': filename,
                'directory': os.path.dirname(relative_path),
                'full_path': full_path,
                'relative_path': relative_path,
                'extension': extension.lower(),
                'size_bytes': os.path.getsize(full_path),
                'year': file_date_info['year'] or dir_date_info['year'],
                'month': file_date_info['month'] or dir_date_info['month'],
                'day': file_date_info['day'] or (dir_date_info['day'] if dir_date_info else None),
            }
            
            try:
                if file_info['year'] and file_info['month'] and file_info['day']:
                    file_info['date'] = f"{file_info['year']}-{file_info['month']:02d}-{file_info['day']:02d}"
                elif file_info['year'] and file_info['month']:
                    file_info['date'] = f"{file_info['year']}-{file_info['month']:02d}"
                elif file_info['year']:
                    file_info['date'] = f"{file_info['year']}"
                else:
                    file_info['date'] = '알 수 없음'
            except:
                file_info['date'] = '알 수 없음'
            
            try:
                mtime = os.path.getmtime(full_path)
                file_info['modified_date'] = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
            except:
                file_info['modified_date'] = '알 수 없음'
            
            file_info_list.append(file_info)
            total_files += 1
            
            if total_files % 10 == 0:
                elapsed = time.time() - start_time
                print(f"진행 중: {total_files}개 PDF 파일, {processed_dirs}개 디렉토리 처리 (경과 시간: {elapsed:.1f}초)")
    
    elapsed = time.time() - start_time
    print(f"\n검색 완료: {total_files}개 PDF 파일, {processed_dirs}개 디렉토리 (총 {elapsed:.1f}초)")
    
    return file_info_list

def save_to_csv(file_info_list, output_file="pdf_files.csv"):
    """
    파일 정보 목록을 CSV 파일로 저장합니다.
    파일명, 연도, 월, 일을 별도 컬럼으로 저장 (월, 일은 두 자리 형식).
    """
    data = []
    for info in file_info_list:
        month_formatted = f"{info['month']:02d}" if info['month'] else ''
        day_formatted = f"{info['day']:02d}" if info['day'] else ''
        
        row = {
            'PDF 파일명': info['filename'],
            '연도': info['year'] if info['year'] else '',
            '월': month_formatted,
            '일': day_formatted
        }
        data.append(row)
    
    df = pd.DataFrame(data)
    
    df.to_csv(output_file, index=False, encoding='utf-8-sig')
    
    print(f"PDF 파일 목록이 '{output_file}' CSV 파일로 저장되었습니다.")

def save_to_excel(file_info_list, output_file="pdf_files.xlsx"):
    """
    파일 정보 목록을 엑셀 파일로 저장합니다.
    파일명, 연도, 월, 일을 별도 컬럼으로 저장.
    """
    try:
        data = []
        for info in file_info_list:
            month_formatted = f"{info['month']:02d}" if info['month'] else ''
            day_formatted = f"{info['day']:02d}" if info['day'] else ''
            
            row = {
                'PDF 파일명': info['filename'],
                '연도': info['year'] if info['year'] else '',
                '월': month_formatted,
                '일': day_formatted
            }
            data.append(row)
        
        df = pd.DataFrame(data)
        
        try:
            with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='PDF 파일 정보', index=False)
            print(f"PDF 파일 목록이 '{output_file}' 엑셀 파일로 저장되었습니다.")
            return True
        except ImportError:
            print("openpyxl 모듈이 설치되어 있지 않아 CSV 파일로 저장합니다.")

            csv_file = os.path.splitext(output_file)[0] + '.csv'
            save_to_csv(file_info_list, csv_file)
            return False
    except Exception as e:
        print(f"파일 저장 중 오류 발생: {e}")
        print("CSV 파일로 저장을 시도합니다.")
        csv_file = os.path.splitext(output_file)[0] + '.csv'
        save_to_csv(file_info_list, csv_file)
        return False

def main():
    """
    메인 함수: 명령줄 인수를 파싱하고 파일 검색을 실행합니다.
    """
    # 명령줄 인수 처리
    if len(sys.argv) < 2:
        print("사용법: python script.py <검색할_디렉토리> [--output <출력_파일명>]")
        return
        
    root_dir = sys.argv[1]
    output_file = "pdf_files.xlsx"
    
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == "--output" and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            break
    
    if not (output_file.lower().endswith('.xlsx') or output_file.lower().endswith('.csv')):
        output_file += '.xlsx'
    
    pdf_files = find_pdf_files(root_dir)
    
    if pdf_files:
        success = save_to_excel(pdf_files, output_file)
        
        if success:
            print(f"\n엑셀 파일에 PDF 파일명, 연도, 월, 일 정보가 포함된 시트가 생성되었습니다.")
        
        print(f"총 {len(pdf_files)}개의 PDF 파일 정보가 저장되었습니다.")
    else:
        print("PDF 파일을 찾을 수 없습니다.")

if __name__ == "__main__":
    main()