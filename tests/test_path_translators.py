from scanners.path_translators import PathMap
from scanners.path_translators import PathMaps


def test_path_translation():
    path_map = PathMaps("id1", "id2", "id3")
    path_map.id1 = PathMap("/q/w/e/r/t", "/y/u/i/o/p")
    path_map.id2 = PathMap("/a/s/d/f/g", "/h/j/k/l")
    path_map.id3 = PathMap("/z/x/c/v", "/b/n/m")

    assert (
        path_map.host_2_container("/a/s/d/f/g/subdir/myfile")
        == "/h/j/k/l/subdir/myfile"
    )
    assert (
        path_map.container_2_host("/b//n/m/subdir/myfile") == "/z/x/c/v/subdir/myfile"
    )
