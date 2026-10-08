"""Ensayo de la migración del historial antiguo sobre una COPIA de un portal_datos.

Solo imprime recuentos, estados y comprobaciones sí/no: ningún nombre, IP, URL,
nombre de fichero ni contenido. Los avisos que el portal escribe en la terminal se
cuentan pero no se muestran. La copia vive en una carpeta temporal y se borra al final.

Uso, desde la carpeta del repo, con el portal cerrado:
    python -m tests.ensayo_migracion RUTA\\portal_datos
"""
import io
import json
import re
import shutil
import sys
import tempfile
import time
from contextlib import closing, redirect_stderr
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path.cwd()))
try:
    from dedalo import auditoria, db, report, web
except ImportError:
    sys.exit("Ejecútalo desde la carpeta del repo de Dédalo.")

ACTIVE = {"en_cola", "en_curso", "deteniendo"}


def redact(text):
    text = re.sub(r"https?://\S+", "<url>", text)
    text = re.sub(r"\d{1,3}(?:\.\d{1,3}){3}", "<ip>", text)
    text = re.sub(r"[A-Za-z]:\\[^'\"\n]*|(?:/[^/'\"\s]+){2,}", "<ruta>", text)
    return text[:120]


def folder_files(folder):
    return {p.relative_to(folder).as_posix(): p.stat().st_size for p in folder.rglob("*") if p.is_file()}


def old_runs(root):
    runs = {}
    for path in sorted(root.glob("*/trabajo.json")):
        folder = path.parent
        if not re.fullmatch(r"[a-f0-9]{32}", folder.name):
            continue
        info = {"ficheros": folder_files(folder)}
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
            info.update(estado=meta.get("estado"), nombre=meta.get("nombre"), archivos=meta.get("archivos"))
        except Exception as exc:
            info["ilegible"] = type(exc).__name__
        try:
            manifest = report.load_manifest(folder / "resultado")
        except Exception:
            manifest = None
        info["estado_motor"] = (manifest or {}).get("estado")
        info["capturadas"] = sum(1 for g in (manifest or {}).get("grupos", []) for r in (g.get("resultados") or [])
                                 if r.get("estado") == "capturada" and r.get("captura"))
        runs[folder.name] = info
    return runs


def start(root):
    output = io.StringIO()
    began = time.perf_counter()
    with redirect_stderr(output):
        store = web.PortalStore(root)
    return store, time.perf_counter() - began, output.getvalue()


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    source = Path(sys.argv[1])
    if not source.is_dir():
        sys.exit("No existe la carpeta indicada.")
    with tempfile.TemporaryDirectory(prefix="dedalo-ensayo-", ignore_cleanup_errors=True) as tmp:
        copy = Path(tmp) / "portal_datos"
        shutil.copytree(source, copy, ignore=shutil.ignore_patterns(".portal.lock"))
        before = old_runs(copy)
        print(f"Copia en carpeta temporal. Ejecuciones antiguas (con trabajo.json): {len(before)}; "
              f"base previa: {'sí' if (copy / 'dedalo.sqlite3').exists() else 'no'}")

        store, first, warnings = start(copy)
        try:
            jobs = dict(store.jobs)
            failures = list(store.migration_failures)
        finally:
            store.close()
        lines = [l for l in warnings.splitlines() if l.strip()]
        print(f"Primer arranque (con migración): {first:.2f} s · avisos en la terminal: {len(lines)} "
              f"(de ellos «sin sus resultados»: {sum('sin sus resultados' in l for l in lines)}) · "
              f"fallos de migración: {len(failures)}")

        problems = 0
        with closing(db.connect(copy)) as con:
            for number, (job_id, old) in enumerate(before.items(), 1):
                if "ilegible" in old:
                    print(f"#{number}: trabajo.json ilegible ({old['ilegible']})")
                    problems += 1
                    continue
                expected = "interrumpida" if old["estado"] in ACTIVE else old["estado"]
                new = jobs.get(job_id)
                capture_id = auditoria.capture_of(con, job_id)
                shots = con.execute("SELECT COUNT(*) FROM captura WHERE ejecucion_id = ? AND estado = 'capturada'",
                                    (capture_id or "",)).fetchone()[0]
                evidence = dict(con.execute("SELECT tipo, COUNT(*) FROM evidencia WHERE ejecucion_id IN (?, ?) GROUP BY tipo",
                                            (job_id, capture_id or "")).fetchall())
                after = folder_files(copy / job_id)
                untouched = {k: v for k, v in after.items() if k != "parar"} == old["ficheros"]
                checks = {
                    "historial": new is not None,
                    "estado": bool(new) and new["estado"] == expected,
                    "nombre": bool(new) and new["nombre"] == old["nombre"],
                    "archivos": bool(new) and new["archivos"] == old["archivos"],
                    "capturas": shots == old["capturadas"],
                    "carpeta intacta": untouched,
                }
                ok = all(checks.values())
                problems += not ok
                state = f"{old['estado']}->{new['estado'] if new else '-'}" + ("" if checks["estado"] else f" (esperado {expected})")
                print(f"#{number} {'OK ' if ok else 'MAL'} estado {state} · motor {old['estado_motor'] or '—'} · "
                      f"capturas {shots}/{old['capturadas']} · evidencias captura {evidence.get('captura', 0)}, "
                      f"registro {evidence.get('registro', 0)}, nmap {evidence.get('nmap', 0)} · "
                      + " · ".join(f"{k} {'sí' if v else 'NO'}" for k, v in checks.items()))
        for failure in failures:
            number = list(before).index(failure["id"]) + 1 if failure["id"] in before else "?"
            print(f"Fallo #{number}: {redact(failure['error'])}")

        store, second, _ = start(copy)
        store.close()
        print(f"Segundo arranque (lo migrado ya no se repite): {second:.2f} s")
        print(f"Resultado: {len(before) - problems}/{len(before)} ejecuciones sin problemas. La copia se borra ahora.")


if __name__ == "__main__":
    main()
