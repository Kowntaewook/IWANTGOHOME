import importlib.util
import json
from pathlib import Path
import zipfile
import pytest
from conftest import ROOT


def packager():
    spec=importlib.util.spec_from_file_location('packager',ROOT/'scripts/package_source.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod


def test_source_zip_allowlist_and_no_overwrite(tmp_path):
    package=packager().package;target=tmp_path/'source.zip'
    result=package(target)
    with zipfile.ZipFile(target) as z:
        names=z.namelist()
        assert result['files']==len(names)>50
        assert all('/workspace/' not in x and '/results/' not in x and 'auth.json' not in x and '.git/' not in x for x in names)
        assert 'something_finder/src/ctf_mcp/server.py' in names
        assert 'something_finder/examples/synthetic/sample.apk' in names
        assert not any('something_finder-main.zip' in x for x in names)
    with pytest.raises(FileExistsError):package(target)


def test_manifest_does_not_sweep_new_files_or_follow_links(tmp_path):
    mod=packager();root=tmp_path/'source';root.mkdir()
    (root/'keep.py').write_text('print("synthetic")\n')
    (root/'release-files.txt').write_text('keep.py\n')
    (root/'auth.json').write_text('SYNTHETIC_NOT_FOR_EXPORT')
    out=tmp_path/'export.zip';mod.package(out,root)
    with zipfile.ZipFile(out) as z:assert z.namelist()==['something_finder/keep.py']
    (root/'keep.py').unlink();(root/'keep.py').symlink_to(root/'auth.json')
    with pytest.raises(ValueError,match='symlinks'):mod.package(tmp_path/'linked.zip',root)
