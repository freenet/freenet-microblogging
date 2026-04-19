const MAX_CHARS = 280;
const WARN_THRESHOLD = 20;

export function createComposeBox(onPost: (content: string) => void): HTMLElement {
  const compose = document.createElement("div");
  compose.className = "compose-box";

  const avatar = document.createElement("div");
  avatar.className = "compose-box__avatar";

  const body = document.createElement("div");
  body.className = "compose-box__body";

  const textarea = document.createElement("textarea");
  textarea.className = "compose-box__textarea";
  textarea.placeholder = "What's happening on Freenet?";
  textarea.rows = 3;
  // Allow textarea to auto-resize
  textarea.style.overflow = "hidden";
  textarea.style.resize = "none";

  const footer = document.createElement("div");
  footer.className = "compose-box__footer";

  const actions = document.createElement("div");
  actions.className = "compose-box__actions";

  // Character counter
  const charCounter = document.createElement("span");
  charCounter.className = "compose-box__char-counter";
  charCounter.textContent = String(MAX_CHARS);

  const postBtn = document.createElement("button");
  postBtn.className = "btn btn--post";
  postBtn.textContent = "Post";
  postBtn.disabled = true;

  function updateTextareaHeight(): void {
    textarea.style.height = "auto";
    textarea.style.height = `${textarea.scrollHeight}px`;
  }

  function updateCounter(): void {
    const remaining = MAX_CHARS - textarea.value.length;
    charCounter.textContent = String(remaining);
    const isOverLimit = remaining < 0;
    const isNearLimit = remaining >= 0 && remaining < WARN_THRESHOLD;

    charCounter.classList.toggle("compose-box__char-counter--warn", isNearLimit);
    charCounter.classList.toggle("compose-box__char-counter--over", isOverLimit);

    postBtn.disabled = textarea.value.trim().length === 0 || isOverLimit;
  }

  textarea.addEventListener("input", () => {
    updateTextareaHeight();
    updateCounter();
  });

  postBtn.addEventListener("click", () => {
    const content = textarea.value.trim();
    if (content.length === 0 || content.length > MAX_CHARS) return;
    onPost(content);
    textarea.value = "";
    textarea.style.height = "auto";
    postBtn.disabled = true;
    charCounter.textContent = String(MAX_CHARS);
    charCounter.classList.remove("compose-box__char-counter--warn", "compose-box__char-counter--over");
  });

  actions.appendChild(charCounter);
  footer.appendChild(actions);
  footer.appendChild(postBtn);

  body.appendChild(textarea);
  body.appendChild(footer);

  compose.appendChild(avatar);
  compose.appendChild(body);

  return compose;
}
