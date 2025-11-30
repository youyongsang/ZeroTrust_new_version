from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from ..db.devices_repo import get_pending_approvals, approve_device

router = APIRouter()

@router.get("/admin", response_class=HTMLResponse)
async def admin_home(request: Request):
    pending = get_pending_approvals()
    html = "<h2>기기 승인 요청 목록</h2><ul>"
    for req in pending:
        html += f"<li>사용자: {req['user_id']} / 기기: {req['device_id']} "
        html += f"<form method='post' action='/admin/approve' style='display:inline'>"
        html += f"<input type='hidden' name='user_id' value='{req['user_id']}'>"
        html += f"<input type='hidden' name='device_id' value='{req['device_id']}'>"
        html += "<button type='submit'>승인</button></form></li>"
    html += "</ul>"
    return HTMLResponse(html)

@router.post("/admin/approve")
async def admin_approve(request: Request):
    form = await request.form()
    user_id = form.get("user_id")
    device_id = form.get("device_id")
    approve_device(user_id, device_id)
    return RedirectResponse("/admin", status_code=303)