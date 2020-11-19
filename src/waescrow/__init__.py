
import sys
if "pytest" in sys.modules:
    from typeguard.importhook import install_import_hook
    install_import_hook('waescrow')
