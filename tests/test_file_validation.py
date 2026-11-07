from io import BytesIO
from werkzeug.datastructures import FileStorage

from app import allowed_file


def make_upload(filename, content):
    return FileStorage(
        stream=BytesIO(content),
        filename=filename
    )


def test_genuine_pdf_is_accepted():
    content = b"%PDF-1.4\nTest PDF content\n"
    uploaded = make_upload("test.pdf", content)

    assert allowed_file("test.pdf", uploaded) is True


def test_fake_pdf_is_rejected():
    content = b"This is only a text file."
    uploaded = make_upload("fake.pdf", content)

    assert allowed_file("fake.pdf", uploaded) is False


def test_genuine_png_is_accepted():
    content = bytes.fromhex(
        "89504e470d0a1a0a"
        "0000000d494844520000000100000001"
        "08060000001f15c489"
        "0000000b49444154789c636000020000"
        "050001a5f64540"
        "0000000049454e44ae426082"
    )

    uploaded = make_upload("test.png", content)

    assert allowed_file("test.png", uploaded) is True


def test_fake_png_is_rejected():
    content = b"This is not an image."
    uploaded = make_upload("fake.png", content)

    assert allowed_file("fake.png", uploaded) is False


def test_invalid_extension_is_rejected():
    content = b"Some content"
    uploaded = make_upload("test.exe", content)

    assert allowed_file("test.exe", uploaded) is False