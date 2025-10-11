@echo off
echo Compiling Java code...
javac src/minecraft.java
if %ERRORLEVEL% neq 0 (
    echo Compilation failed!
    pause
    exit /b 1
)

echo Creating manifest file...
echo Main-Class: minecraft > Manifest.txt

echo Creating JAR file...
cd src
jar cvmf ..\Manifest.txt ..\server.jar *.class
cd ..
if %ERRORLEVEL% neq 0 (
    echo JAR creation failed!
    pause
    exit /b 1
)

echo Cleaning up...
del Manifest.txt
del src\*.class
echo Compilation successful! server.jar created.
pause
