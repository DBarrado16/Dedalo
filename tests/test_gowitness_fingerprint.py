import sqlite3
import tempfile
import unittest
from pathlib import Path

from dedalo import gowitness


def build_gowitness_db(path, url):
    """Una base como la que escribe gowitness v3: results + headers + technologies."""
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE results (id INTEGER PRIMARY KEY, url TEXT, final_url TEXT, response_code INTEGER,
                              title TEXT, html TEXT);
        CREATE TABLE headers (id INTEGER PRIMARY KEY, result_id INTEGER, key TEXT, value TEXT);
        CREATE TABLE technologies (id INTEGER PRIMARY KEY, result_id INTEGER, value TEXT);
    """)
    html = '<html><head><title>Panel</title><meta name="generator" content="WordPress 6.4.2"></head></html>'
    rid = con.execute("INSERT INTO results (url, final_url, response_code, title, html) VALUES (?, ?, ?, ?, ?)",
                       (url, url, 200, "Panel", html)).lastrowid
    con.executemany("INSERT INTO headers (result_id, key, value) VALUES (?, ?, ?)",
                    [(rid, "Server", "nginx/1.18.0"), (rid, "X-Powered-By", "PHP/7.4.33")])
    con.executemany("INSERT INTO technologies (result_id, value) VALUES (?, ?)",
                    [(rid, "WordPress:6.4.2"), (rid, "PHP:7.4.33")])
    con.commit()
    con.close()


class ReadFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / gowitness.DB_NAME

    def tearDown(self):
        self.temp.cleanup()

    def test_returns_headers_technologies_and_html_by_normalized_url(self):
        url = "http://10.10.5.3:80/"
        build_gowitness_db(self.db, url)
        data = gowitness.read_fingerprint(self.db)
        key = gowitness.normalize_url(url)
        self.assertIn(key, data)
        row = data[key]
        self.assertEqual(row["headers"]["Server"], "nginx/1.18.0")
        self.assertEqual(row["headers"]["X-Powered-By"], "PHP/7.4.33")
        self.assertEqual(sorted(row["technologies"]), ["PHP:7.4.33", "WordPress:6.4.2"])
        self.assertIn("WordPress 6.4.2", row["html"])
        self.assertEqual(row["title"], "Panel")
        self.assertEqual(row["response_code"], 200)

    def test_missing_database_returns_empty(self):
        self.assertEqual(gowitness.read_fingerprint(self.db), {})

    def test_database_without_rows_returns_empty(self):
        build_gowitness_db(self.db, "http://10.10.5.3:80/")
        con = sqlite3.connect(self.db)
        con.execute("DELETE FROM results")
        con.commit()
        con.close()
        self.assertEqual(gowitness.read_fingerprint(self.db), {})


if __name__ == "__main__":
    unittest.main()
