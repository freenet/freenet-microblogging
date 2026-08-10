<script lang="ts">
  import { APP_NAME, APP_LOGO_URL } from "../branding";

  let { onComplete }: {
    onComplete: (displayName: string, secretKey?: string) => void;
  } = $props();

  let name = $state("");
  let importName = $state("");
  let importSecret = $state("");
  let showImport = $state(false);

  let nameInput: HTMLInputElement | undefined = $state();

  const joinDisabled = $derived(name.trim().length === 0);
  const importDisabled = $derived(
    importName.trim().length === 0 || importSecret.trim().length !== 64
  );

  function submitJoin() {
    const n = name.trim();
    if (!n) return;
    onComplete(n);
  }

  function submitImport() {
    const n = importName.trim();
    const secret = importSecret.trim();
    if (!n || secret.length !== 64) return;
    onComplete(n, secret);
  }

  function onNameKeydown(e: KeyboardEvent) {
    if (e.key === "Enter") submitJoin();
  }

  $effect(() => {
    nameInput?.focus();
  });
</script>

<div class="onboarding-overlay">
  <div class="onboarding-card">
    <img
      class="onboarding-logo"
      src={APP_LOGO_URL}
      alt={`${APP_NAME} logo`}
      draggable="false"
    />
    <div class="onboarding-tagline">Decentralized Microblog</div>
    <h1 class="onboarding-title">Welcome to {APP_NAME}</h1>
    <p class="onboarding-subtitle">Choose your display name to get started</p>

    <div class="onboarding-section" style:display={showImport ? "none" : "flex"}>
      <input
        bind:this={nameInput}
        class="onboarding-input"
        type="text"
        placeholder="Your name"
        maxlength="50"
        autocomplete="off"
        spellcheck="false"
        bind:value={name}
        onkeydown={onNameKeydown}
      />
      <button class="onboarding-btn" disabled={joinDisabled} onclick={submitJoin}>
        Join
      </button>
    </div>

    <ul class="onboarding-facts">
      <li>
        <strong>Posts are public and permanent.</strong> Anyone can read them, and
        there is no delete — a post leaves the network only once ~200 newer ones
        have pushed it out of your shard.
      </li>
      <li>
        <strong>Your key is your account.</strong> It is generated on this device
        and never sent anywhere. Lose it and the identity is gone for good; there
        is no reset, and nobody can restore it for you.
      </li>
      <li>
        <strong>Who you follow is public too.</strong> Your follow list lives in
        your own shard, which anyone can read.
      </li>
    </ul>

    <button class="onboarding-import-link" onclick={() => (showImport = !showImport)}>
      Import existing identity
    </button>

    <div class="onboarding-section" style:display={showImport ? "flex" : "none"}>
      <input
        class="onboarding-input"
        type="text"
        placeholder="Your name"
        maxlength="50"
        bind:value={importName}
      />
      <input
        class="onboarding-input onboarding-input--mono"
        type="password"
        placeholder="Secret key (64 hex characters)"
        maxlength="64"
        bind:value={importSecret}
      />
      <button class="onboarding-btn" disabled={importDisabled} onclick={submitImport}>
        Import
      </button>
    </div>
  </div>
</div>
