# Tightlip motion

Enter uses `cubic-bezier(0.22, 1, 0.36, 1)`. Move uses `cubic-bezier(0.25, 1, 0.5, 1)`. Pointer actions use the timings below. Keyboard actions update immediately and retain focus. With reduced motion, sealing, opening, starting another note, and burning use a 120 ms opacity crossfade. Other changes are immediate. Browsers without same-document View Transitions switch states directly.

| Moment | Timing | Reduced motion |
| --- | --- | --- |
| Content type | The Tab bar indicator moves in 180 ms, Move. The note content shifts 8 px, entering in 180 ms, Enter, and exiting in 130 ms, Move. | Immediate |
| Sentence options | The popover enters from its trigger in 150 ms, Enter. Values and the inline password field update directly. | Immediate |
| Files | The upload icon lifts 4 px in 160 ms, Enter. New thumbnails rise in 140 ms, Enter, and removed ones fade in 120 ms, Move, where element matching is supported. | Static drop cue and immediate thumbnails |
| Upload | The primary press scales to .97 in 130 ms, Enter. The Sweep button fills in 160 ms, Move, as worker progress arrives. | Immediate progress |
| Seal | The paper folds into the 120 px strip using a transform FLIP and View Transitions over 320 ms, Move. The wax settles 6 px from scale 1.15 over 180 ms, Enter. The link then writes left to right over 300 ms, Enter. | 120 ms crossfade |
| Copy | The two pages join and the check scales in over 150 ms, Enter. The check rests for 1.2 s, then returns over 150 ms. | Immediate check and return |
| Burn hold | Hold for 900 ms to confirm. The fill advances linearly and rewinds in 130 ms, Enter, if released early. | Static holding cue, same hold duration |
| Break the seal | The wax halves move apart, rotate 12 degrees and fade over 220 ms, Enter. The note unfolds over 320 ms, Move. The Text blur rise brings the content in over 210 ms, Enter. Images fade in after decoding over 180 ms. | 120 ms crossfade once ready |
| Burn | After a successful owner burn or closing a last view, the full paper fades and scales to .98 over 400 ms, Move. The dust samples paper geometry. The ash or new note fades in during the final 180 ms. Browser navigation clears recipient content on `pagehide`. | 120 ms crossfade |
| Wrong password | The inline error appears and focus returns to the field. The field shakes 4 px to either side over 250 ms, Enter. | Immediate focus and message |
| Show or hide a revealed password | The eye and mask crossfade over 150 ms, Enter. The field keeps its size. | Immediate |
| Views left | The counter rolls from the count shown before opening to the count returned by the server over 180 ms, Move, starting after the unfold. Real text sets the digit baseline and supplies the accessible value. | Immediate |

The Bencho Tab bar, Upload dropzone, Sweep button, Copy field, Hold to delete, Text blur, Dust delete, Form error, Password reveal, Password strength, and Rolling counter are adapted under the Bencho Pro licence. The Pay button morph and Toast stack are retired. The tab labels stay visible, the strength checklist gives way to a thin meter, and errors sit underneath the note's sentence.

Sound starts off. The footer toggle saves the sound preference. Bencho Nib plays on taps, Check on successful copy, and Toss on a successful owner burn or when the recipient closes a last view.
