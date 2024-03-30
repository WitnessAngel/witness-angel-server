import pathlib, sys
import pytest, os

@pytest.hookimpl(tryfirst=True)
def pytest_load_initial_conftests(early_config, parser, args):

    root_dir = pathlib.Path(__file__).resolve().parents[0]
    assert (root_dir / "manage.py").exists(), root_dir / "manage.py"
    sys.path.append(str(root_dir / "src"))

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "waserver.settings")
    import django_compat_patcher
    django_compat_patcher.patch(settings=dict(
        DCP_INCLUDE_FIXER_IDS=[],
        DCP_INCLUDE_FIXER_FAMILIES=["django4.1", "django4.0"]))
