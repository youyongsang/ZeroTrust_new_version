// ===== 설정 =====
const API_BASE = "http://localhost:8000";
console.log("app.js OTP build v6"); // 로딩 확인용

// ===== 유틸 =====
async function http(method, path, data) {
  const init = {
    method,
    headers: { "Content-Type": "application/json" },
    credentials: "include",
  };
  if (data !== undefined) init.body = JSON.stringify(data);
  let res, text, json;
  try {
    res = await fetch(`${API_BASE}${path}`, init);
    text = await res.text();
    try { json = JSON.parse(text); } catch { json = { raw: text }; }
    return { ok: res.ok, status: res.status, data: json };
  } catch (e) { return { ok: false, status: 0, data: { error: String(e) } }; }
}
const $ = (id) => document.getElementById(id);
const setMsg = (el, v) => { if (el) el.textContent = typeof v === "string" ? v : JSON.stringify(v, null, 2); };
const show = (id, on=true) => { const el=$(id); if (el) el.style.display = on ? "" : "none"; };

// ===== 세션 표시 =====
async function loadMe() {
  const out = $("meBox");
  setMsg(out, "확인 중...");
  const r = await http("GET", "/me");
  if (r.ok) {
    const user = r.data.user ?? r.data;
    setMsg(out, user);
    if (user && user.id) {
      show("btnLogout", true);
    } else {
      show("btnLogout", false);
    }
    // 가입/등록 UI는 기본 숨김
    show("regStepEmail", true);
    show("regStepCode", false);
    show("totpBox", false);
    show("mfaBox", false);
  } else {
    setMsg(out, r);
  }
}

// ===== 회원가입 1단계: 시작(이메일+비번 제출, 코드 발송) =====
async function onRegisterStart() {
  const email = $("regEmail")?.value.trim();
  const password = $("regPassword")?.value ?? "";
  const msg = $("regMsg");
  if (!email || !password) return setMsg(msg, "이메일/비밀번호를 입력하세요.");

  setMsg(msg, "코드 발송 중...");
  const r = await http("POST", "/auth/register/start", { email, password });
  setMsg(msg, r);
  if (r.ok) {
    // 다음 스텝(코드 입력) 노출
    show("regStepEmail", false);
    show("regStepCode", true);
    $("regEmailCode")?.focus();
  }
}

// ===== 회원가입 2단계: 이메일 코드 검증 → QR/SECRET 표시 =====
async function onVerifyEmailCode() {
  const code = $("regEmailCode")?.value.trim();
  const msg  = $("regCodeMsg");
  if (!code) return setMsg(msg, "인증코드를 입력하세요.");

  setMsg(msg, "확인 중...");
  const r = await http("POST", "/auth/register/verify-email-code", { code });
  setMsg(msg, r);
  if (r.ok) {
    // QR/SECRET 표시(가입용 totpBox 재사용)
    renderEnrollTotp(r.data.secret, r.data.otpauth_url);
  }
}

// ===== 회원가입 3단계: 첫 OTP 검증 → 최종 가입 완료(+로그인) =====
async function onActivateTotpRegister() {
  const code = $("totpActivateCode")?.value.trim();
  const msg  = $("totpActivateMsg");
  if (!code) return setMsg(msg, "앱에 표시된 6자리 코드를 입력하세요.");
  setMsg(msg, "확인 중...");

  const r = await http("POST", "/auth/register/activate-totp", { code });
  setMsg(msg, r);
  if (r.ok) {
    // 백업코드 표시 & 상태 갱신
    const backup = $("backupList");
    backup.innerHTML = "";
    (r.data.backup_codes || []).forEach(c => {
      const li = document.createElement("li"); li.textContent = c;
      if (!backup.firstChild) backup.appendChild(document.createElement("ul"));
      backup.firstChild.appendChild(li);
    });
    setMsg(msg, "가입 완료! 로그인 상태로 전환되었습니다.");
    show("totpBox", false);
    await loadMe();
  }
}

// ===== 로그인(1단계) =====
async function onLogin() {
  const email = $("email")?.value.trim();
  const password = $("password")?.value ?? "";
  const msg = $("loginMsg");
  if (!email || !password) return setMsg(msg, "이메일/비밀번호를 입력하세요.");

  setMsg(msg, "로그인 시도 중...");
  const r = await http("POST", "/auth/login", { email, password });
  setMsg(msg, r);

  if (r.ok && r.data && r.data.mfa_required) {
    show("mfaBox", true);
    setMsg($("mfaMsg"), "OTP(6자리)를 입력하세요.");
    $("otpCode")?.focus();
    return;
  }
}

// ===== 로그인 2단계 =====
async function onVerifyOtp() {
  const code = $("otpCode")?.value.trim();
  const msg  = $("mfaMsg");
  if (!code) return setMsg(msg, "OTP 코드를 입력하세요.");
  setMsg(msg, "검증 중...");

  const r = await http("POST", "/auth/mfa/totp/verify-login", { code });
  setMsg(msg, r);
  if (r.ok) { show("mfaBox", false); await loadMe(); }
}

// ===== 로그아웃 =====
async function onLogout() {
  const out = $("outMsg");
  setMsg(out, "로그아웃 중...");
  const r = await http("POST", "/auth/logout", {});
  setMsg(out, r);
  await loadMe();
}

// ===== 공용: 가입용 QR/SECRET 렌더 =====
function renderEnrollTotp(secret, otpauth) {
  show("totpBox", true);
  setMsg($("totpInfo"), "인증앱으로 QR을 스캔하고, 앱의 6자리 코드를 입력해 완료하세요.");
  if ($("totpSecret")) $("totpSecret").textContent = secret || "";
  const a = $("totpUrl");
  if (a) { a.textContent = otpauth || ""; a.setAttribute("href", otpauth || "#"); }
  const qr = $("qrBox");
  if (qr) {
    qr.innerHTML = "";
    if (otpauth && window.QRCode) {
      const canvas = document.createElement("canvas");
      qr.appendChild(canvas);
      QRCode.toCanvas(canvas, otpauth, { width: 192, margin: 1 }).catch(console.error);
    }
  }
}

// ===== 초기 바인딩 =====
window.addEventListener("DOMContentLoaded", () => {
  // 세션/로그인
  $("btnRefresh")?.addEventListener("click", loadMe);
  $("btnLogout")?.addEventListener("click", onLogout);
  $("btnLogin")?.addEventListener("click", onLogin);
  $("btnOtp")?.addEventListener("click", onVerifyOtp);

  // 회원가입(3단계)
  $("btnRegisterStart")?.addEventListener("click", onRegisterStart);
  $("btnVerifyEmailCode")?.addEventListener("click", onVerifyEmailCode);
  $("btnActivateTotp")?.addEventListener("click", onActivateTotpRegister);

  // 사용하지 않는 버튼 숨김
  const hideIds = ["btnStartTotp", "btnDisableTotp"];
  hideIds.forEach(id => show(id, false));

  loadMe();
});
