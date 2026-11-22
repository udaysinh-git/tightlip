export function Security(props: { back: (event: MouseEvent) => void }) {
  return (
    <article class="paper security" aria-labelledby="security-title">
      <h1 id="security-title">How a secret stays secret</h1>
      <p class="lead">Your browser encrypts the note before it leaves. The server keeps something it cannot read,
        and destroys its half of the lock on time.</p>

      <figure class="link-anatomy" aria-label="The two halves of a Tightlip link">
        <div class="link-half">
          <code>tightlip…/s/9hQ2mTkV4xWc7LrA0dNe1g</code>
          <figcaption>Sent to the server. It says which note, nothing more.</figcaption>
        </div>
        <div class="link-half link-key">
          <code>#Jc5u_Yw3pXo8RkqZ…</code>
          <figcaption>The key. Browsers never send the part after the #.</figcaption>
        </div>
      </figure>

      <h2>When you seal a note</h2>
      <ol>
        <li>Your browser makes a random 256-bit key and encrypts the note with XChaCha20-Poly1305.
          Photos lose their location and camera data first.</li>
        <li>Only the encrypted note is uploaded. It is padded, so its size gives away little about its length.</li>
        <li>The key is placed after the # in the link, the part that stays in the browser.</li>
        <li>Opening the link also needs one answer from the server, and the server gives a limited number of them.
          A share password is checked through that same answer, so every guess uses one up.</li>
      </ol>

      <div class="ledger">
        <section>
          <h2>What the server keeps</h2>
          <ul>
            <li>The encrypted note</li>
            <li>When it expires</li>
            <li>Views and tries left</li>
            <li>Whether it has a password</li>
          </ul>
        </section>
        <section>
          <h2>What it never receives</h2>
          <ul>
            <li>The key</li>
            <li>The password</li>
            <li>The text or the files</li>
            <li>File names and types</li>
          </ul>
        </section>
      </div>

      <h2>When it burns</h2>
      <p>After the last view or the expiry, the server destroys the secret value only it held.
        A saved copy of the link and of the encrypted note cannot be opened without it.</p>

      <h2>What this cannot do</h2>
      <ul>
        <li>Stop the person who reads the note from copying it.</li>
        <li>Protect you from the server that delivers this page. It sends your browser the code that does the
          encrypting, so a server that was taken over could send different code. A strict content policy and
          integrity hashes make that harder. They do not make it impossible.</li>
        <li>Hide the note from malware or a shared screen on either end.</li>
        <li>Point to an outside audit. Tightlip has not had one yet.</li>
      </ul>

      <p class="security-foot">
        <button class="quiet-button" type="button" onClick={(event) => props.back(event)}>Write a secret</button>
        <span>Built by <a href="https://www.kurolabs.in" target="_blank" rel="noopener noreferrer">KuroLabs</a>.</span>
      </p>
    </article>
  );
}
