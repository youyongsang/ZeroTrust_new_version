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
  // QRCode 라이브러리 체크 및 오류 안내 강화
  if (otpauth && window.QRCode && typeof window.QRCode.toCanvas === "function") {
    const canvas = document.createElement("canvas");
    el.appendChild(canvas);
    QRCode.toCanvas(canvas, otpauth, { width: 192, margin: 1 }, (err) => {
      if (err) {
        console.error("QR render error:", err);
        el.innerHTML = "<p class='mono small'>QR 코드 생성 중 오류가 발생했습니다.</p>";
      }
    });
  } else {
    const p = document.createElement("p");
    p.className = "mono small";
    if (!window.QRCode) {
      p.textContent = "(QR 라이브러리가 로드되지 않았습니다. 스크립트 경로를 확인하세요)";
    } else if (!otpauth) {
      p.textContent = "(QR 코드 URI가 비어 있습니다)";
    } else {
      p.textContent = "(QR 코드 생성 함수가 없습니다)";
    }
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

  // 로그인 상태에 따라 UI 제어
  if (user && user.email) {
    // 로그인된 상태: 로그인/회원가입 박스 숨김
    show("loginBox", false);
    show("registerBox", false);
    show("logoutBox", true); // 로그아웃 버튼 등은 보여줌
  } else {
    // 로그아웃 상태: 로그인/회원가입 박스 표시
    show("loginBox", true);
    show("registerBox", true);
    show("logoutBox", false);
  }
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

  // locked 처리: 서버가 429과 retry_after를 보낼 때
  if (r && (r.status === 429 || (r.data && r.data.locked))) {
    const secs = (r.data && r.data.retry_after) ? r.data.retry_after : null;
    if (secs !== null) {
      alert(`연속된 로그인 실패로 제한이 걸렸습니다. ${secs}초 후에 다시 시도해 주세요.`);
    } else {
      alert("연속된 로그인 실패로 제한이 걸렸습니다. 잠시 후 다시 시도해 주세요.");
    }
    return;
  }

  // 새 기기 → 이메일 승인 필요
  if (r.ok && r.data && r.data.device_required) {
    console.log(r.data.device_required);
    return setMsg(
      msg,
      `새 기기 로그인 승인 메일을 보냈습니다. 메일의 링크를 이 브라우저에서 열고, 다시 로그인하세요. (dev_id: ${devId})`
    );
  }

  // 최초 활성화 단계: 첫 코드 입력 (이제 QR은 안 보여줌)
  if (r.ok && r.data && r.data.next === "otp") {
    setMsg($("mfaMsg"), "앱의 6자리 코드를 입력하세요.");
    show("mfaBox", true);
    return;
  }

}

// ==== OTP 검증(로그인 중) ====
async function onVerifyOtp() {
  console.log("onVerifyOtp");
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
    alert("로그인에 성공했습니다.");
    location.reload();
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
    const { otpauth_url } = r.data.totp;
    renderQR($("qrBoxReg"), otpauth_url || "");
    setMsg($("totpRegInfo"), "인증앱(Google/Microsoft Authenticator 등)으로 QR을 스캔해 등록하세요.");
    show("totpRegBox", true);
  }
}

// ==== 최초 TOTP 활성화 & 회원가입 완료 ====
async function onActivateTotpReg() {
  const code = $("totpActivateCode")?.value.trim();
  const msg = $("totpActivateMsg");
  if (!code) return setMsg(msg, "앱의 6자리 코드를 입력하세요.");
  setMsg(msg, "활성화 중...");

  // 서버에 OTP 활성화 요청
  const r = await http("POST", "/auth/mfa/totp/activate", { code });
  setMsg(msg, r);

  if (r.ok) {
    $("totpActivateCode").value = "";
    show("totpRegBox", false);
    alert("회원가입이 완료되었습니다.");
    location.reload();
  }
}

// ==== 바인딩 ====
window.addEventListener("DOMContentLoaded", () => {
  $("btnLogin")?.addEventListener("click", onLogin);
  $("btnLogout")?.addEventListener("click", onLogout);
  $("btnRefresh")?.addEventListener("click", loadMe);
  $("btnRegister")?.addEventListener("click", onRegister);

  $("btnOtp")?.addEventListener("click", onVerifyOtp); // 로그인용 OTP
  $("btnActivateTotp")?.addEventListener("click", onActivateTotpReg); // 회원가입용 OTP

  $("btnVerifyEmailCode")?.addEventListener("click", onVerifyEmailCode);

  getDevId();
  loadMe();
});
