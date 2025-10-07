// ==== 설정 ====
// 같은 서버에서 정적과 API를 같이 서빙 중이면 빈 문자열("")을 사용하세요.
const API_BASE = "";

// ==== 유틸 ====
// 브라우저 고유 dev_id 생성/보관
function getDevId() {
  let id = localStorage.getItem("dev_id");
  if (!id) {
    if (crypto && typeof crypto.randomUUID === "function") {
      id = crypto.randomUUID();
    } else {
      id = "dev-" + Math.random().toString(36).slice(2) + "-" + Date.now();
    }
    localStorage.setItem("dev_id", id);
  }
  return id;
}

async function http(method, path, data) {
  const init = { method, credentials: "include", headers: {} };
  if (data !== undefined) { // 바디 있을 때만 JSON 헤더(불필요한 preflight 방지)
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(data);
  }
  const res = await fetch(`${API_BASE}${path}`, init);
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { ok: res.ok, status: res.status, data: json };
}

function $(id) { return document.getElementById(id); }
function show(idOrEl, on = true) {
  const el = typeof idOrEl === "string" ? $(idOrEl) : idOrEl;
  if (!el) return;
  el.style.display = on ? "" : "none";
}
function setMsg(el, obj) {
  if (!el) return;
  el.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
}
function renderQR(el, otpauth) {
  if (!el) return;
  el.innerHTML = "";
  if (otpauth && window.QRCode) {
    const canvas = document.createElement("canvas");
    el.appendChild(canvas);
    QRCode.toCanvas(canvas, otpauth, { width: 192, margin: 1 }, (err) => {
      if (err) console.error("QR render error:", err);
    });
  } else {
    console.log(window.QRCode);
    console.log(otpauth);
    const p = document.createElement("p");
    p.className = "mono small";
    p.textContent = "(QR 라이브러리가 없거나 URI가 비어 있음)";
    el.appendChild(p);
  }
}

// ==== 세션 상태 ====
async function loadMe() {
  const out = $("meBox");
  if (out) out.textContent = "확인 중...";
  const r = await http("GET", "/me");
  const user = r.ok ? (r.data.user ?? r.data) : null;
  setMsg(out, user);
}

// ==== 로그인 ====
async function onLogin() {
  const email = $("email")?.value.trim();
  const password = $("password")?.value ?? "";
  const msg = $("loginMsg");
  setMsg(msg, "로그인 시도 중...");
  if (!email || !password) return setMsg(msg, "이메일/비밀번호를 입력하세요.");

  // dev_id 항상 포함
  const devId = getDevId();

  // UI 초기화
  show("mfaBox", false);
  show("totpActivateBox", false);

  const r = await http("POST", "/auth/login", { email, password, dev_id: devId });
  setMsg(msg, r);

  // 새 기기 → 이메일 승인 필요
  if (r.ok && r.data && r.data.device_required) {
    return setMsg(
      msg,
      `새 기기 로그인 승인 메일을 보냈습니다. 메일의 링크를 이 브라우저에서 열고, 다시 로그인하세요. (dev_id: ${devId})`
    );
  }

  // 신뢰 기기 OK → 다음 단계 분기
  if (r.ok && r.data && r.data.next === "activate_totp") {
    // 최초 활성화 단계: QR + 첫 코드 입력
    const totp = r.data.totp || {};
    $("totpActSecret").textContent = totp.secret || "";
    const u = $("totpActUrl");
    if (u) { u.textContent = totp.otpauth_url || ""; u.setAttribute("href", totp.otpauth_url || "#"); }
    renderQR($("qrBoxAct"), totp.otpauth_url || "");
    setMsg($("totpActivateInfo"), "인증앱을 등록하고 6자리 코드를 입력하세요.");
    show("totpActivateBox", true);
    return;
  }

  if (r.ok && r.data && r.data.next === "otp") {
    // 일반 OTP 입력 단계
    setMsg($("mfaMsg"), "앱의 6자리 코드를 입력하세요.");
    show("mfaBox", true);
    return;
  }

  // 이미 모든 단계 통과 → 로그인 완결
  if (r.ok) {
    $("password").value = "";
    await loadMe();
  } else {
    if (r.status === 401) setMsg(msg, "이메일 또는 비밀번호가 올바르지 않습니다.");
    if (r.status === 403) setMsg(msg, "이메일 미인증 상태입니다. 받은 편지함을 확인하세요.");
  }
}

// ==== OTP 검증(로그인 중) ====
async function onVerifyOtp() {
  const code = $("otpCode")?.value.trim();
  const msg = $("mfaMsg");
  if (!code) return setMsg(msg, "OTP 코드를 입력하세요.");
  setMsg(msg, "검증 중...");
  const r = await http("POST", "/auth/mfa/totp/verify-login", { code });
  setMsg(msg, r);
  if (r.ok) {
    $("otpCode").value = "";
    show("mfaBox", false);
    await loadMe();
  }
}

// ==== 최초 TOTP 활성화 & 로그인 ====
async function onActivateTotp() {
  const code = $("totpActivateCode")?.value.trim();
  const msg = $("totpActivateMsg");
  if (!code) return setMsg(msg, "앱의 6자리 코드를 입력하세요.");
  setMsg(msg, "활성화 중...");

  const r = await http("POST", "/auth/mfa/totp/activate", { code });
  setMsg(msg, r);

  if (r.ok) {
    // 백업코드 1회 표시
    const backup = $("backupList");
    if (backup) {
      backup.innerHTML = "";
      const codes = r.data.backup_codes || [];
      if (codes.length) {
        const ul = document.createElement("ul");
        codes.forEach(c => { const li = document.createElement("li"); li.textContent = c; ul.appendChild(li); });
        backup.appendChild(ul);
      } else {
        backup.textContent = "(백업코드 없음)";
      }
    }
    $("totpActivateCode").value = "";
    // 로그인 완료
    show("totpActivateBox", false);
    await loadMe();
  }
}

// ==== 로그아웃 ====
async function onLogout() {
  const outMsg = $("outMsg");
  setMsg(outMsg, "로그아웃 중...");
  const r = await http("POST", "/auth/logout", {});
  setMsg(outMsg, r);
  await loadMe();
}

// ==== 회원가입: 코드 전송만 ====
async function onRegister() {
  const email = $("regEmail")?.value.trim();
  const password = $("regPass")?.value;
  const msg = $("regMsg");
  if (!email || !password) return setMsg(msg, "이메일/비밀번호를 입력하세요.");

  setMsg(msg, "가입 중...");
  const r = await http("POST", "/auth/register", { email, password });
  setMsg(msg, r);
  if (r.ok) {
    $("regPass").value = "";
    // 이전 QR 표시가 있으면 숨김/초기화
    show("totpRegBox", false);
    $("qrBoxReg").innerHTML = "";
    $("totpRegSecret").textContent = "";
    $("totpRegUrl").textContent = "";
    setMsg($("totpRegInfo"), "받은 메일의 6자리 코드를 아래에 입력하고 확인을 누르세요.");
  }
}

// ==== 이메일 인증코드 확인 → QR 표시 ====
async function onVerifyEmailCode() {
  const email = $("regEmail")?.value.trim();
  const code = $("emailCode")?.value.trim();
  const msg  = $("emailCodeMsg");
  if (!email || !code) return setMsg(msg, "이메일과 인증코드를 입력하세요.");

  setMsg(msg, "확인 중...");
  const r = await http("POST", "/auth/verify-email-code", { email, code });
  setMsg(msg, r);

  if (r.ok && r.data && r.data.totp) {
    const { secret, otpauth_url } = r.data.totp;
    $("totpRegSecret").textContent = secret || "";
    const u = $("totpRegUrl");
    if (u) { u.textContent = otpauth_url || ""; u.setAttribute("href", otpauth_url || "#"); }
    renderQR($("qrBoxReg"), otpauth_url || "");
    setMsg($("totpRegInfo"), "인증앱(Google/Microsoft Authenticator 등)으로 QR을 스캔해 등록하세요.");
    show("totpRegBox", true);
  }
}

// ==== 바인딩 ====
window.addEventListener("DOMContentLoaded", () => {
  $("btnLogin")?.addEventListener("click", onLogin);
  $("btnLogout")?.addEventListener("click", onLogout);
  $("btnRefresh")?.addEventListener("click", loadMe);
  $("btnRegister")?.addEventListener("click", onRegister);

  $("btnOtp")?.addEventListener("click", onVerifyOtp);
  $("btnActivateTotp")?.addEventListener("click", onActivateTotp);

  $("btnVerifyEmailCode")?.addEventListener("click", onVerifyEmailCode);

  getDevId();
  loadMe();
});
