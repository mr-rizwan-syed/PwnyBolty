import os
import traceback
import string
import secrets
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks


from src.models import CFCOPayload
from src.logging import log_request, GlobalLogger
from src.consts import BUILD_DIR
from src.builder import build_func

app = FastAPI(title="CFCO API Server")

@app.post("/build")
@app.post("/api/build")
async def build(
    payload: CFCOPayload, 
    req: Request, 
    background_task: BackgroundTasks):
    """
        Build payload
    """
    generate_buildid = lambda: ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    try:
        # Log request
        log_request(req)

        # generate buildid
        buildid = generate_buildid()
        GlobalLogger.info("Started build #%s", buildid)

        # Create a build folder 
        build_dir = os.path.join(BUILD_DIR, buildid)
        os.makedirs(build_dir, exist_ok=True)

        # start builder task
        background_task.add_task(build_func, buildid, payload)

        return {'buildid': buildid}

    except Exception as e:
        GlobalLogger.error("Exception occured as %s", e)
        GlobalLogger.error("Traceback: %s", traceback.format_exc())
        raise HTTPException(status_code=500)
