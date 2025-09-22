// ==== 설정 ====
// API 서버 주소 — 필요시 바꿔주세요.
// 정적파일을 FastAPI가 같이 서빙 중이면 빈 문자열("")로 두세요.
const API_BASE = "http://127.0.0.1:8000";

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
  const init = {
    method,
    headers: { "Content-Type": "application/json" },
    credentials: "include", // 세션/디바이스 쿠키 주고받기
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
  if (!el) return;
  el.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
}

// ==== 상태 불러오기 ====
async function loadMe() {
  const out = $("meBox");
  if (out) out.textContent = "확인 중...";
  const r = await http("GET", "/me");
  if (r.ok) {
    // 서버가 { ok:true, user:{...} } 형태라면:
    const user = r.data.user ?? r.data; // 유연하게 처리
    setMsg(out, user);
  } else {
    setMsg(out, { status: r.status, data: r.data });
  }
}

// ==== 로그인 (디바이스 인증 지원) ====
async function onLogin() {
  const emailEl = $("email");
  const passEl = $("password");
  const msg = $("loginMsg");
  if (!emailEl || !passEl) {
    return setMsg(msg, "로그인 입력 요소를 찾을 수 없습니다. HTML id를 확인하세요.");
  }
  const email = emailEl.value.trim();
  const password = passEl.value;

  setMsg(msg, "로그인 시도 중...");
  if (!email || !password) {
    return setMsg(msg, "이메일/비밀번호를 입력하세요.");
  }

  // 브라우저 고유 dev_id 동봉
  const devId = getDevId();

  const r = await http("POST", "/auth/login", { email, password, dev_id: devId });
  setMsg(msg, r);

  if (r.ok && r.data && r.data.device_required) {
    // 새 기기 → 메일로 온 승인 링크를 '이 브라우저'에서 열고, 다시 로그인 버튼을 누르도록 안내
    setMsg(
      msg,
      `새 기기 로그인 승인 메일을 보냈습니다. 메일의 링크를 이 브라우저에서 열고, 다시 로그인하세요.\n(dev_id: ${devId})`
    );
    return;
  }

  if (r.ok) {
    // 서버가 세션 쿠키를 내려줬다면 상태 갱신
    passEl.value = "";
    await loadMe();
  } else {
    // 오류 케이스 보조 메시지
    if (r.status === 401) setMsg(msg, "이메일 또는 비밀번호가 올바르지 않습니다.");
    if (r.status === 403) setMsg(msg, "이메일 미인증 상태입니다. 받은 편지함을 확인하세요.");
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

// ==== 회원가입 ====
async function onRegister() {
  const emailEl = $("regEmail");
  const passEl = $("regPass") || $("regPassword"); // 과거/새 id 모두 허용
  const msg = $("regMsg");
  if (!emailEl || !passEl) {
    return setMsg(msg, "회원가입 입력 요소를 찾을 수 없습니다. HTML id를 확인하세요.");
  }

  const email = emailEl.value.trim();
  const password = passEl.value;
  setMsg(msg, "가입 중...");

  if (!email || !password) return setMsg(msg, "이메일/비밀번호를 입력하세요.");

  const r = await http("POST", "/auth/register", { email, password });
  setMsg(msg, r);
  if (r.ok) {
    setMsg(msg, "가입 완료. 이메일의 인증 링크를 눌러주세요. (SMTP 미설정이면 서버 콘솔 확인)");
    passEl.value = "";
  }
}

// ==== 이벤트 바인딩 ====
window.addEventListener("DOMContentLoaded", () => {
  $("btnLogin")?.addEventListener("click", onLogin);
  $("btnLogout")?.addEventListener("click", onLogout);
  $("btnRefresh")?.addEventListener("click", loadMe);
  $("btnRegister")?.addEventListener("click", onRegister);

  // dev_id가 없다면 선 생성(최초 1회)
  getDevId();
  loadMe();
});
