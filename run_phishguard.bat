@echo off
echo Starting PhishGuard Full Stack Environment...

:: Start Flask Backend
start "PhishGuard Backend" cmd /k "python app.py"

:: Wait for backend to initialize
timeout /t 5 /nobreak

:: Start Next.js Frontend
cd frontend
start "PhishGuard Frontend" cmd /k "npm run dev"

echo.
echo ===================================================
echo PhishGuard is running!
echo Backend: http://127.0.0.1:5000
echo Frontend: http://localhost:3000
echo.
echo Dashboard should open automatically...
echo ===================================================

:: Wait for frontend to initialize
timeout /t 5 /nobreak

:: Open Dashboard
start http://localhost:3000/dashboard
