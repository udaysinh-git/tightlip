export function Security(props: { back: (event: MouseEvent) => void }) {
  return (
    <article class="paper security" aria-labelledby="security-title">
      <h1 id="security-title">How a secret stays secret</h1>
      <p class="lead">Your browser encrypts shares before upload. The server holds a wrapped key that
        it uses to answer a limited number of requests.</p>

      <figure class="link-anatomy" aria-label="The two halves of a Tightlip link">
        <div class="link-half">
          <code>tightlip…/s/9hQ2mTkV4xWc7LrA0dNe1g</code>
          <figcaption>The share ID in the HTTP request.</figcaption>
        </div>
        <div class="link-half link-key">
          <code>#Jc5u_Yw3pXo8RkqZ…</code>
          <figcaption>The key follows the #. HTTP requests omit it. Browsers can store and sync the full link, including the key, in history.</figcaption>
        </div>
      </figure>

      <h2>When you seal a note</h2>
      <ol>
        <li>Your browser makes a random 256-bit key and encrypts the note with XChaCha20-Poly1305.
          The client strips common camera and location metadata from JPEG, PNG and WebP photos before upload.</li>
        <li>The client uploads encrypted content and share settings. Padding hides the exact content length within a size bucket.</li>
        <li>Send the key separately to let the recipient paste it without putting it in the address bar.</li>
        <li>Opening the link also needs one answer from the server, and the server gives a limited number of them.
          A share password is checked through that same answer, so every guess uses one up.</li>
        <li>For new shares, the browser sends a credential derived from the link key before the server returns share details or counts an attempt.</li>
      </ol>

      <div class="ledger">
        <section>
          <h2>What the server keeps</h2>
          <ul>
            <li>Share ID, expiry, pending deadline and password flag</li>
            <li>View and attempt counts, final attempt deadline and wrapped server key</li>
            <li>Encrypted content, file indices, blob identifiers and padded file sizes</li>
            <li>Hashes used to authorize uploads, share details, attempts, opens, downloads and deletion</li>
            <li>Grant deadlines and hashes of successful open requests with their deadlines and view counts</li>
            <li>Storage totals and records of files awaiting deletion</li>
          </ul>
        </section>
        <section>
          <h2>What stays in the intended client</h2>
          <ul>
            <li>The link key</li>
            <li>The password</li>
            <li>The text or the files</li>
            <li>File names and types</li>
          </ul>
        </section>
      </div>

      <h2>When it burns</h2>
      <p>Views count new opens by holders of the access tag. One recipient can use all of them.
        After the last view or expiry, the server logically deletes its wrapped key. Files remain available
        to existing download grants for up to 10 minutes. Old blocks and storage snapshots can retain copies.</p>

      <h2>What this cannot do</h2>
      <ul>
        <li>Stop the person who reads the note from copying it.</li>
        <li>Protect you from a server that replaces this page and its code. Content security policy and Trusted Types
          limit some injection. Browser integrity checks compare covered files with the hashes in the delivered
          code. An independent comparison uses a trusted copy of the release manifest.</li>
        <li>Hide the note from malware or a shared screen on either end.</li>
        <li>Hide what you type from browser extensions with access to the page.</li>
      </ul>

      <p class="security-foot">
        <button class="quiet-button" type="button" onClick={(event) => props.back(event)}>Write a secret</button>
        <span>Built by <a href="https://www.kurolabs.in" target="_blank" rel="noopener noreferrer">KuroLabs</a>.</span>
      </p>
    </article>
  );
}
