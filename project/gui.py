import sys
import yara
import os
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QFileDialog, QTextEdit, QVBoxLayout
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtCore import Qt

class MalwareScanner(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()
        self.yara_rules = self.load_yara_rules('악성코드/project/yar_folder')  # 룰 폴더 경로 (여러 .yar 파일이 들어있는 폴더)

    def initUI(self):
        self.setWindowTitle('악성코드 탐지 프로그램')
        self.setGeometry(100, 100, 600, 400)  # 윈도우 크기를 600x400으로 설정

        layout = QVBoxLayout()

        # 제목 레이블
        self.label = QLabel('파일을 선택하세요:')
        self.label.setFont(QFont("Arial", 14, QFont.Weight.Bold))  # 폰트 스타일 설정
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.label)

        # 파일 선택 버튼
        self.select_button = QPushButton('파일 선택')
        self.select_button.setFont(QFont("Arial", 12))
        self.select_button.setStyleSheet("background-color: #4CAF50; color: white; border-radius: 10px; padding: 10px;")
        self.select_button.clicked.connect(self.select_file)
        layout.addWidget(self.select_button)

        # 결과 텍스트 표시 영역
        self.result_text = QTextEdit(self)
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet("""
            background-color: #f1f1f1; 
            color: #333333;  # 텍스트 색상을 어두운 회색으로 설정
            border-radius: 10px; 
            padding: 10px; 
            font-size: 14px;
        """)
        layout.addWidget(self.result_text)

        # 탐지 실행 버튼
        self.scan_button = QPushButton('탐지 실행')
        self.scan_button.setFont(QFont("Arial", 12))
        self.scan_button.setStyleSheet("background-color: #008CBA; color: white; border-radius: 10px; padding: 10px;")
        self.scan_button.clicked.connect(self.scan_file)
        layout.addWidget(self.scan_button)

        self.setLayout(layout)

    def load_yara_rules(self, rules_folder):
        yara_rules = yara.compile(filepaths=self.get_yara_files_in_folder(rules_folder))
        return yara_rules

    def get_yara_files_in_folder(self, folder_path):
        # 폴더에서 .yar 파일을 찾아서 리스트로 반환
        yara_files = {}
        for filename in os.listdir(folder_path):
            if filename.endswith(".yar"):
                filepath = os.path.join(folder_path, filename)
                yara_files[filename] = filepath
        return yara_files

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, '파일 선택', '', 'All Files (*)')
        if file_path:
            self.label.setText(f'선택된 파일: {file_path}')
            self.selected_file = file_path

    def scan_file(self):
        if hasattr(self, 'selected_file'):
            try:
                matches = self.yara_rules.match(self.selected_file)  # 여러 YARA 룰을 적용하여 파일 탐지
                if matches:
                    result_text = "🔴 악성코드 탐지됨!\n"
                    for match in matches:
                        result_text += f"룰: {match.rule}\n"
                        print(f"탐지된 룰: {match.rule}")  # 매칭된 룰 로그 출력
                    self.result_text.setText(result_text)
                else:
                    self.result_text.setText("✅ 안전한 파일입니다.")
            except Exception as e:
                self.result_text.setText(f"오류 발생: {str(e)}")
        else:
            self.result_text.setText("파일을 먼저 선택하세요.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    scanner = MalwareScanner()
    scanner.show()
    sys.exit(app.exec())
