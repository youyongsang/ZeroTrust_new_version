// ==== 설정 ====
// API 서버 주소 — 필요시 바꿔주세요.
// 서버가 세션 쿠키를 쓰므로 fetch에는 credentials: "include" 가 꼭 필요합니다.
const API_BASE = "";

// ==== 유틸 ====
async function http(method, path, data) {
  const init = {
    method,
    headers: { "Content-Type": "application/json" },
    credentials: "include", // 세션 쿠키 주고받기
  };
  if (data !== undefined) init.body = JSON.stringify(data);

  let res, text, json;
  try {
    res = await fetch(`${API_BASE}${path}`, init);
    text = await res.text();
    try { json = JSON.parse(text); } catch { json = { raw: text }; }
    return { ok: res.ok, status: res.status, data: json };
  } catch (err) {
    return { ok: false, status: 0, data: { error: String(err) } };
  }
}

function $(id) { return document.getElementById(id); }
function setMsg(el, obj) {
  el.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
}

// ==== 상태 불러오기 ====
async function loadMe() {
  const out = $("meBox");
  out.textContent = "확인 중...";
  const r = await http("GET", "/me");
  if (r.ok) {
    // 서버가 { ok:true, user:{...} } 형태라면:
    const user = r.data.user ?? r.data; // 유연하게 처리
    setMsg(out, user);
  } else {
    setMsg(out, { status: r.status, data: r.data });
  }
}

// ==== 로그인 ====
async function onLogin() {
  const email = $("email").value.trim();
  const password = $("password").value;
  const msg = $("loginMsg");
  setMsg(msg, "로그인 시도 중...");

  if (!email || !password) {
    return setMsg(msg, "이메일/비밀번호를 입력하세요.");
  }

  const r = await http("POST", "/auth/login", { email, password });
  setMsg(msg, r);

  if (r.ok) {
    // 서버가 세션 쿠키를 내려줬다면 상태 갱신
    await loadMe();
    $("password").value = "";
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

async function onRegister() {
  const email = $("regEmail").value.trim();
  const password = $("regPass").value;
  const msg = $("regMsg");
  setMsg(msg, "가입 중...");

  if (!email || !password) return setMsg(msg, "이메일/비밀번호를 입력하세요.");

  const r = await http("POST", "/auth/register", { email, password });
  setMsg(msg, r);
  if (r.ok) {
    setMsg(msg, "가입 완료. 이메일의 인증 링크를 눌러주세요. (SMTP 미설정이면 서버 콘솔 확인)");
  }
}


// ==== 이벤트 바인딩 ====
window.addEventListener("DOMContentLoaded", () => {
  $("btnLogin").addEventListener("click", onLogin);
  $("btnLogout").addEventListener("click", onLogout);
  $("btnRefresh").addEventListener("click", loadMe);
  $("btnRegister").addEventListener("click", onRegister);
  loadMe();
});
