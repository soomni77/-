import pefile
import hashlib
import yara
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# ==============================
# 1. 파일 해시 계산 함수
# ==============================
def calculate_hash(file_path):
    """파일의 SHA-256 해시값을 계산합니다."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# ==============================
# 2. PE 파일 분석 함수
# ==============================
def analyze_pe(file_path):
    """PE 파일의 헤더와 섹션을 분석합니다."""
    try:
        pe = pefile.PE(file_path)
        result = f"\n[+] 분석 중: {file_path}\n"
        
        # DOS 헤더와 PE 헤더 정보
        result += f"  DOS Header Magic: {hex(pe.DOS_HEADER.e_magic)}\n"
        result += f"  PE Header Signature: {hex(pe.NT_HEADERS.Signature)}\n"
        
        # 섹션 정보 출력
        result += "\n[+] 섹션 정보:\n"
        for section in pe.sections:
            result += f"  Section Name: {section.Name.decode().strip()}, Size: {section.SizeOfRawData}\n"
        
        # 임포트 테이블 정보
        result += "\n[+] 임포트된 함수들:\n"
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            result += f"  Library: {entry.dll.decode()}\n"
            for imp in entry.imports:
                result += f"    {imp.name.decode() if imp.name else 'Unknown'}\n"
                
        return result
    except Exception as e:
        return f"[!] PE 파일 분석 중 오류 발생: {e}"

# ==============================
# 3. YARA 룰 매칭 함수
# ==============================
def scan_with_yara(file_path, yara_rules_folder):
    """폴더 내의 모든 YARA 룰을 사용하여 파일을 분석합니다."""
    try:
        # 룰 폴더가 올바른지 확인
        if not os.path.isdir(yara_rules_folder):
            raise ValueError(f"YARA 룰 폴더가 잘못되었습니다: {yara_rules_folder}")
        
        # 룰 파일 목록 가져오기
        rule_files = [os.path.join(yara_rules_folder, f) for f in os.listdir(yara_rules_folder) if f.endswith('.yar') or f.endswith('.yara')]
        
        if not rule_files:
            raise ValueError("YARA 룰 파일이 폴더에 없습니다.")
        
        # 여러 룰 파일을 컴파일
        rules = yara.compile(filepaths={f: f for f in rule_files})
        
        # 룰 매칭
        matches = rules.match(file_path)
        if matches:
            result = "\n[+] YARA 룰 매칭 결과:\n"
            for match in matches:
                result += f"  룰: {match.rule}\n"
            return result
        else:
            return "[+] YARA 룰에서 매칭된 결과 없음."
    except Exception as e:
        return f"[!] YARA 룰 매칭 중 오류 발생: {e}"

# ==============================
# 4. 문자열 추출 함수
# ==============================
def extract_strings(file_path):
    """파일에서 문자열을 추출하고, 의심스러운 문자열을 찾습니다."""
    with open(file_path, "rb") as f:
        file_data = f.read()
        # 4바이트 이상의 문자열 추출
        strings = [s.decode(errors="ignore") for s in file_data.split(b'\x00') if len(s) > 3]
        result = "\n[+] 추출된 문자열 (상위 10개):\n"
        for s in strings[:10]:
            result += f"  {s}\n"
        return result

# ==============================
# 5. 파일 선택 및 분석 시작 함수
# ==============================
def select_file():
    """사용자가 파일을 선택할 수 있도록 파일 탐색기를 띄웁니다."""
    file_path = filedialog.askopenfilename(title="분석할 파일 선택", filetypes=(("Executable Files", "*.exe"), ("All Files", "*.*")))
    return file_path

def select_yara_folder():
    """사용자가 YARA 룰 폴더를 선택할 수 있도록 폴더 탐색기를 띄웁니다."""
    folder_path = filedialog.askdirectory(title="YARA 룰 폴더 선택")
    return folder_path

def run_analysis():
    """GUI에서 분석을 실행합니다."""
    file_path = select_file()
    if not file_path:
        messagebox.showerror("오류", "파일을 선택하지 않았습니다.")
        return
    
    yara_rules_folder = select_yara_folder()
    if not yara_rules_folder:
        messagebox.showerror("오류", "YARA 룰 폴더를 선택하지 않았습니다.")
        return

    # 로딩 상태 표시
    start_button.config(state=tk.DISABLED)
    text_output.delete(1.0, tk.END)  # 이전 결과를 지우고
    text_output.insert(tk.END, "분석 중...\n")

    # 1. 파일 해시 계산
    file_hash = calculate_hash(file_path)
    result = f"\n[+] 파일 해시 (SHA-256): {file_hash}\n"
    
    # 2. PE 파일 분석
    result += analyze_pe(file_path)
    
    # 3. YARA 룰 매칭
    result += scan_with_yara(file_path, yara_rules_folder)
    
    # 4. 문자열 추출
    result += extract_strings(file_path)
    
    # 결과 출력
    text_output.delete(1.0, tk.END)  # 이전 결과를 지우고
    text_output.insert(tk.END, result)  # 새로운 결과를 출력

    # 분석 완료 후 버튼 활성화
    start_button.config(state=tk.NORMAL)

# ==============================
# 6. GUI 설정
# ==============================
root = tk.Tk()
root.title("정적 분석 도구")
root.geometry("800x600")  # 창 크기 설정
root.config(bg="#f0f0f0")

# 스타일 설정 (ttk)
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=10, relief="flat", background="#4CAF50", foreground="white")
style.configure("TText", font=("Courier New", 10), relief="sunken", height=15, width=95)

# GUI 레이아웃 설정
frame = tk.Frame(root, bg="#f0f0f0")
frame.pack(pady=20)

start_button = ttk.Button(frame, text="분석 시작", command=run_analysis)
start_button.pack()

text_output = tk.Text(root, wrap=tk.WORD, height=20, width=100)
text_output.pack(pady=10, padx=20)

# 스크롤바 추가
scrollbar = tk.Scrollbar(root, command=text_output.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
text_output.config(yscrollcommand=scrollbar.set)

# 실행
root.mainloop()
