from scanners.path_translators import make_mapping_for_scanner


def test_path_translation():
    id1 = ("id1", "/q/w/e/r/t", "/y/u/i/o/p")
    id2 = ("id2", "/a/s/d/f/g", "/h/j/k/l")
    id3 = ("id3", "/z/x/c/v", "/b/n/m")
    path_map = make_mapping_for_scanner("Test", id1, id2, id3)

    assert (
        path_map.host_2_container("/a/s/d/f/g/subdir/myfile")
        == "/h/j/k/l/subdir/myfile"
    )
    assert (
        path_map.container_2_host("/b//n/m/subdir/myfile") == "/z/x/c/v/subdir/myfile"
    )
