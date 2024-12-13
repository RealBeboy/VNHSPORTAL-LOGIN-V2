@echo off
echo Installing required libraries...

REM Install tkinter (if needed, as tkinter is typically included with Python)
echo Tkinter should already be installed. If not, you can install it via the Python installer.

REM Install Selenium
pip install selenium

REM Install requests
pip install requests

REM Install futures
pip install futures

echo Installation complete!
pause
