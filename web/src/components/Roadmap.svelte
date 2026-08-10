<script lang="ts">
  import { ROADMAP, type RoadmapItem } from "../roadmap-data";

  // Voting is not built yet. Rather than hide the affordance, show it disabled
  // with an honest label — a greyed control that says why is more useful than a
  // surprise later, and it keeps the layout honest about where counts will go.
  const VOTING_LIVE = false;

  const STATUS_LABEL: Record<RoadmapItem["status"], string> = {
    done: "Shipped",
    building: "In progress",
    next: "Committed",
    considering: "Undecided",
  };

  const EFFORT_LABEL: Record<RoadmapItem["effort"], string> = {
    small: "Small",
    medium: "Medium",
    large: "Large",
  };

  const totalVotable = ROADMAP.flatMap((s) => s.items).filter((i) => i.votable).length;
</script>

<main class="feed-column screen">
  <div class="masthead">
    <div class="masthead__row">
      <div>
        <div class="kicker">Where this is going</div>
        <div class="masthead__title">Roadmap</div>
      </div>
    </div>
    <p class="roadmap-intro">
      Everything below is stated at the size it actually is, including the parts
      that are missing and the trade-offs that have no clean answer. Items marked
      <span class="roadmap-chip roadmap-chip--breaks">new addresses</span> change
      the contracts, which means existing shards move and the network redeploys.
    </p>
    {#if !VOTING_LIVE}
      <div class="roadmap-note">
        <strong>Voting is not live yet.</strong>
        {totalVotable} items are open for it. Counts will come from the network — signed,
        one per identity — not from a number typed into this page.
      </div>
    {/if}
  </div>

  <div class="roadmap">
    {#each ROADMAP as section (section.heading)}
      <section class="roadmap-section">
        <h2 class="roadmap-section__title">{section.heading}</h2>
        <p class="roadmap-section__blurb">{section.blurb}</p>

        {#each section.items as item (item.id)}
          <article class="roadmap-item roadmap-item--{item.status}">
            <div class="roadmap-item__head">
              <h3 class="roadmap-item__title">{item.title}</h3>
              <span class="roadmap-chip roadmap-chip--{item.status}">
                {STATUS_LABEL[item.status]}
              </span>
            </div>

            <p class="roadmap-item__summary">{item.summary}</p>
            {#if item.rationale}
              <p class="roadmap-item__rationale">{item.rationale}</p>
            {/if}

            <div class="roadmap-item__foot">
              <span class="roadmap-chip">{EFFORT_LABEL[item.effort]}</span>
              {#if item.breaksAddresses}
                <span class="roadmap-chip roadmap-chip--breaks">new addresses</span>
              {/if}
              {#if item.votable}
                <button
                  class="roadmap-vote"
                  disabled={!VOTING_LIVE}
                  title={VOTING_LIVE
                    ? "Vote for this"
                    : "Voting is not live yet — this will be a signed, one-per-identity vote"}
                >
                  Vote
                </button>
              {/if}
            </div>
          </article>
        {/each}
      </section>
    {/each}
  </div>
</main>
