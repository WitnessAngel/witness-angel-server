echo "Launching the build of waescrow executable"
pyinstaller --clean -F --name waescrow src/prod_runner.py
echo "If success, the generated executable should be in dist/ folder"
# --distpath ../dist --workpath ../build
