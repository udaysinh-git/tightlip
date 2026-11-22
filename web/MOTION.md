# Tightlip motion

Enter uses `cubic-bezier(0.22, 1, 0.36, 1)`. Move uses `cubic-bezier(0.25, 1, 0.5, 1)`. The durations below apply to pointer actions. Keyboard actions update immediately and keep their focus rings. Reduced motion and browsers without same-document View Transitions use immediate state changes. The hold confirmation still requires 900 ms.

| Moment | Timing and curve | Reduced motion |
| --- | --- | --- |
| Content tabs | Tab bar's single indicator moves in 180 ms, Move. The content slides 10 px, with a 190 ms Enter and a 145 ms Move exit. The active label swaps in 160 ms, Enter. | Immediate selection |
| Expiry and views | New value enters vertically in 180 ms, Enter. Old value exits in 120 ms, Move. | Immediate value |
| Password option | Panel enters from the upper right in 190 ms, Enter, and exits in 140 ms, Move. Password strength uses an instant four-segment readout and a checklist as the person types. | Immediate panel and strength |
| File drop and removal | Drop zone grows to 1.02 in 180 ms, Move. Its icon lifts 4 px in 180 ms, Enter. New rows enter over 140 ms, Enter, offset by 40 ms per row. The delay caps at 160 ms. The remaining rows move in 180 ms, Move, and removed rows fade in 120 ms. | Static border cue and immediate rows |
| Create and upload | Press feedback scales to 0.97 in 130 ms, Enter. The button and progress share one transition name. The morph enters in 260 ms, Enter, and exits in 155 ms, Move. The fill moves in 160 ms, Move, from worker upload events. | Immediate meter and progress |
| Link created | The composer and link field share a transition name. The result enters in 260 ms, Enter, with a 155 ms Move exit. The URL uncovers left to right in 350 ms, Enter. | Immediate result |
| Copy | The back page moves into the front as both fade. The check enters from 0.8 scale in 150 ms, Enter, holds 1.2 s, then returns in 150 ms. | Immediate check and return |
| Delete | A linear fill runs for 900 ms and rewinds in 130 ms, Enter. A completed delete enters the empty composer in 260 ms, Enter, with a 155 ms Move exit. | Static hold cue and immediate composer |
| Reveal | The sealed panel exits in 190 ms, Move. The new panel uncovers top to bottom in 520 ms, Enter. Login rows enter in 180 ms, Enter, spaced by 40 ms. Images fade in over 180 ms after decoding. | Immediate content once ready, including decoded images |
| Last view | Close share fades and scales the outgoing panel to 0.98 in 400 ms, Move. The lazy dust layer releases grains from the windward edge over the same 400 ms. The gone message enters in the last 180 ms, Enter. Browser navigation clears content on `pagehide`. | Immediate removal |
| Wrong password | Error message enters in 180 ms, Enter. The focused input moves 4 px in each direction twice over 250 ms. | Border and message only |
| Show and hide secrets | Eye and mask crossfade in 150 ms, Enter. The field keeps its size. | Immediate mask and icon |
| Views left | Odometer strips move in 180 ms, Move, with 45 ms between digit columns. The count comes from `/open` after reveal. | Immediate count |
| Toasts | New messages enter in 180 ms, Enter. The three-item stack fans out on fine-pointer hover in 240 ms, Move. | Static list |

Tab bar supplies a single moving indicator. Text blur supplies the quiet one-shot arrival through its rise variation. Cheaper transforms, opacity, and clipping preserve those effects within Tightlip's timing and animation rules. The Sweep button's leading edge follows real progress, and Pay button's shared footprint carries the change from action to meter.

Sound is off initially. The footer toggle saves only the sound preference. Bencho Nib plays on taps, Check on successful copy, and Toss on closing a last view.
