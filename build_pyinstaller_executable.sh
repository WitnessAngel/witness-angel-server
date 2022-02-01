echo "Launching the build of watrustee executable"
pyinstaller --clean -F --name waserver src/prod_runner.py
echo "If success, the generated executable should be in dist/ folder"
# --distpath ../dist --workpath ../build
