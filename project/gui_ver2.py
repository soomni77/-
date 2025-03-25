from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QFileDialog,
    QTextEdit, QLabel, QStackedWidget, QHBoxLayout
)
import sys
import pefile
import hashlib
import yara
import zipfile
import os

class MalwareAnalysisApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("정적 분석 도구")
        self.setGeometry(100, 100, 900, 600)
        
        self.layout = QVBoxLayout()
        
        # 스택 위젯: 초기 화면 / 분석 결과 화면 전환
        self.stack = QStackedWidget()
        
        # 첫 화면: 분석 시작 버튼만
        self.start_screen = QWidget()
        start_layout = QVBoxLayout()
        self.start_button = QPushButton("분석 시작")
        self.start_button.clicked.connect(self.run_analysis)
        start_layout.addWidget(self.start_button)
        self.start_screen.setLayout(start_layout)
        
        # 분석 결과 화면
        self.result_screen = QWidget()
        result_layout = QVBoxLayout()
        
        # 결과 창을 2x2 레이아웃으로 배치
        grid_layout = QHBoxLayout()
        self.pe_zip_analysis_text = QTextEdit()
        self.pe_zip_analysis_text.setReadOnly(True)
        self.basic_info_text = QTextEdit()
        self.basic_info_text.setReadOnly(True)
        self.yara_analysis_text = QTextEdit()
        self.yara_analysis_text.setReadOnly(True)
        
        grid_layout.addWidget(QLabel("기본 정보"))
        grid_layout.addWidget(self.basic_info_text)
        grid_layout.addWidget(QLabel("PE & Zip 분석"))
        grid_layout.addWidget(self.pe_zip_analysis_text)
        grid_layout.addWidget(QLabel("YARA 분석"))
        grid_layout.addWidget(self.yara_analysis_text)
        
        result_layout.addLayout(grid_layout)
        
        # 분석 다시 하기 버튼 추가
        self.retry_button = QPushButton("분석 다시 하기")
        self.retry_button.clicked.connect(self.reset_to_start)
        result_layout.addWidget(self.retry_button)
        
        self.result_screen.setLayout(result_layout)
        
        self.stack.addWidget(self.start_screen)
        self.stack.addWidget(self.result_screen)
        
        self.layout.addWidget(self.stack)
        self.setLayout(self.layout)

        # 프로그램 실행 경로에서 YARA 룰 폴더 경로 설정
        self.yara_rules_folder = os.path.join(os.path.dirname(sys.argv[0]), "yara_rules")
        
    def calculate_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def analyze_pe(self, file_path):
        try:
            pe = pefile.PE(file_path)
            result = "[PE 분석 결과]\n"
            result += f"DOS Header Magic: {hex(pe.DOS_HEADER.e_magic)}\n"
            result += f"PE Header Signature: {hex(pe.NT_HEADERS.Signature)}\n\n"
            result += "[섹션 정보]\n"
            for section in pe.sections:
                result += f"  {section.Name.decode().strip()} | 크기: {section.SizeOfRawData}\n"
            return result
        except Exception as e:
            return f"[!] PE 파일 분석 오류: {e}"
    
    # ZIP 기반 파일 분석 결과
    def analyze_zip_based_file(self, file_path):
        result = "[ZIP 기반 파일 분석 결과]\n"
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                result += f"내부 파일 개수: {len(file_list)}\n"
                result += "[내부 파일 목록]\n"
                for f in file_list[:5]:
                    result += f"  - {f}\n"
                if "xl/vbaProject.bin" in file_list:
                    result += "\n🚨 VBA 매크로 포함됨!\n"
                else:
                    result += "\n✔ VBA 매크로 없음\n"
        except Exception as e:
            result += f"[!] ZIP 분석 오류: {e}"
        return result
    
    # YARA 룰로 EXE 파일 탐지
    def scan_with_yara(self, file_path):
        try:
            if not os.path.isdir(self.yara_rules_folder):
                return "[!] YARA 룰 폴더 오류"
            
            rule_files = [os.path.join(self.yara_rules_folder, f) for f in os.listdir(self.yara_rules_folder) if f.endswith('.yar') or f.endswith('.yara')]
            if not rule_files:
                return "YARA 룰 파일 없음."
            
            rules = yara.compile(filepaths={f: f for f in rule_files})
            result = "[YARA 탐지 결과]\n"
            matches = rules.match(file_path)
            if matches:
                for match in matches:
                    result += f"  - {match.rule}\n"
            else:
                result += "✔ 탐지 결과 없음\n"
            return result
        except Exception as e:
            return f"[!] YARA 분석 오류: {e}"

    # YARA 룰로 EXE 파일을 검사하는 함수
    def scan_exe_with_yara(self, file_path):
        return self.scan_with_yara(file_path)

    # Xlsm 파일에서 VBA 매크로 파일을 추출하여 YARA 룰로 검사
    def scan_xlsm_with_yara(self, file_path):
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                if "xl/vbaProject.bin" in zip_ref.namelist():
                    # 'xl/vbaProject.bin'을 추출하여 YARA 룰로 검사
                    with zip_ref.open("xl/vbaProject.bin") as vba_file:
                        vba_file_path = "vbaProject.bin"  # 임시 저장 경로
                        with open(vba_file_path, 'wb') as temp_file:
                            temp_file.write(vba_file.read())

                        # YARA 룰 적용
                        result = self.scan_with_yara(vba_file_path)
                        
                        # 임시 파일 삭제
                        os.remove(vba_file_path)
                        return result
                else:
                    return "✔ 매크로 없음"
        except Exception as e:
            return f"[!] YARA 분석 오류: {e}"

    # 파일 분석 실행 함수
    def run_analysis(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "파일 선택", "", "모든 파일 (*.*)")
        if not file_path:
            return
        
        self.basic_info_text.clear()
        self.pe_zip_analysis_text.clear()
        self.yara_analysis_text.clear()
        
        self.basic_info_text.setText(f"파일 경로: {file_path}\nSHA-256 해시: {self.calculate_hash(file_path)}\n")
        
        # 파일 확장자에 따라 PE 파일 또는 ZIP 파일 분석
        if file_path.endswith(".exe"):
            self.pe_zip_analysis_text.setText(self.analyze_pe(file_path))
            self.yara_analysis_text.setText(self.scan_exe_with_yara(file_path))
        elif file_path.endswith((".xlsm", ".docx", ".pptx", ".zip")):
            self.pe_zip_analysis_text.setText(self.analyze_zip_based_file(file_path))
            self.yara_analysis_text.setText(self.scan_xlsm_with_yara(file_path))
        
        self.stack.setCurrentWidget(self.result_screen)
    
    # 분석 다시 하기 함수
    def reset_to_start(self):
        self.stack.setCurrentWidget(self.start_screen)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MalwareAnalysisApp()
    window.show()
    sys.exit(app.exec())
