<script lang="ts">
  import type { Post } from "../types";
  import { identity } from "../stores/freenet";
  import { MAX_CONTENT_BYTES, contentLength } from "../utils";

  const ICON_CLOSE = `<svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <line x1="4" y1="4" x2="14" y2="14"/>
  <line x1="14" y1="4" x2="4" y2="14"/>
</svg>`;

  const ICON_IMAGE = `<svg width="17" height="17" viewBox="0 0 17 17" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
  <rect x="2" y="3" width="13" height="11" rx="1.5"/>
  <circle cx="6" cy="7" r="1.2"/>
  <path d="M3 12l3-3 3 2 5-4"/>
</svg>`;

  function getInitials(displayName: string): string {
    return displayName
      .split(" ")
      .slice(0, 2)
      .map((w) => w[0])
      .join("")
      .toUpperCase();
  }

  interface Props {
    open: boolean;
    quoted?: Post;
    label?: string;
    placeholder?: string;
    buttonLabel?: string;
    onSubmit: (content: string, shareToGlobal: boolean) => void;
    onClose: () => void;
  }

  let {
    open,
    quoted,
    label,
    placeholder,
    buttonLabel,
    onSubmit,
    onClose,
  }: Props = $props();

  let text = $state("");
  let shareChecked = $state(false);

  let textareaEl: HTMLTextAreaElement | undefined = $state();

  // Budget in UTF-8 bytes, matching what the contract enforces. The old
  // `MAX_CHARS - text.length` was wrong twice over: the cap was 300 against a
  // contract limit of 280, and `.length` under-counts every non-ASCII character.
  const remaining = $derived(MAX_CONTENT_BYTES - contentLength(text));
  const empty = $derived(text.trim().length === 0);
  const postDisabled = $derived((empty && !quoted) || remaining < 0);

  const headLabel = $derived(
    label ?? (quoted ? "Quote · signed locally" : "New post · signed locally"),
  );
  const ph = $derived(
    placeholder ?? (quoted ? "Add a comment…" : "What's happening on the network?"),
  );
  const btnLabel = $derived(buttonLabel ?? (quoted ? "Quote" : "Post"));
  const avatarInitials = $derived($identity ? getInitials($identity.displayName) : "·");

  function close(): void {
    onClose();
  }

  function submit(): void {
    const content = text.trim();
    if (contentLength(content) > MAX_CONTENT_BYTES) return;
    if (content.length === 0 && !quoted) return;
    onSubmit(content, quoted ? false : shareChecked);
    close();
  }

  function onOverlayClick(e: MouseEvent): void {
    if (e.target === e.currentTarget) close();
  }

  $effect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent): void {
      if (e.key === "Escape") {
        close();
      } else if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        submit();
      }
    }
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  });

  $effect(() => {
    if (open && textareaEl) {
      const el = textareaEl;
      requestAnimationFrame(() => el.focus());
    }
  });
</script>

{#if open}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="compose-modal-overlay" onclick={onOverlayClick}>
    <div class="compose-modal" onclick={(e) => e.stopPropagation()}>
      <div class="compose-modal__head">
        <button class="compose-modal__close" aria-label="Close" onclick={close}>
          {@html ICON_CLOSE}
        </button>
        <span class="compose-modal__label">{headLabel}</span>
        <span style="width: 28px;"></span>
      </div>

      <div class="compose-modal__body">
        <div class="compose-modal__avatar">{avatarInitials}</div>
        <textarea
          bind:this={textareaEl}
          class="compose-modal__textarea"
          rows="4"
          placeholder={ph}
          bind:value={text}
        ></textarea>
      </div>

      {#if quoted}
        <div class="compose-modal__quote">
          <div class="compose-modal__quote-head">
            <span class="compose-modal__quote-name">{quoted.author.displayName}</span>
            <span class="compose-modal__quote-handle">@{quoted.author.handle}</span>
          </div>
          <div class="compose-modal__quote-text">{quoted.content}</div>
        </div>
      {/if}

      <div class="compose-modal__foot">
        <div class="compose-modal__tools">
          <button class="compose-modal__tool" aria-label="Attach image">
            {@html ICON_IMAGE}
          </button>
          {#if !quoted}
            <label class="compose-modal__share">
              <input
                type="checkbox"
                class="compose-modal__share-check"
                bind:checked={shareChecked}
              />
              <span>Share to public timeline</span>
            </label>
          {/if}
        </div>
        <div class="compose-modal__meta">
          <span class="compose-modal__count" class:compose-modal__count--over={remaining < 0}>
            {remaining}
          </span>
          <button class="compose-modal__post" onclick={submit} disabled={postDisabled}>
            {btnLabel}
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}
