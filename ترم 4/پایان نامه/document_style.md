# Thesis Word Document Style Guide

This file records the formatting rules and troubleshooting knowledge for `Thesis.docx`.
Use it as the project-specific reference before making future Word changes.

## Document

- Main file: `Thesis.docx`
- Language and writing direction: Persian/Farsi, right-to-left
- The document contains Persian text, Persian numerals, English technical terms, figures, tables, headings, and Word fields.
- Preserve the existing body content, figures, tables, citations, page breaks, and heading hierarchy unless the requested change explicitly affects them.

## Table of contents

The main table of contents must look like the white-background reference image:

- A centered title: `فهرست مطالب`
- A header row:
  - `عنوان` on the right
  - `صفحه` on the left
- Right-to-left layout
- Dotted leaders between entry text and page number
- Page numbers aligned consistently on the left
- Entries should remain on one line where the page width allows
- The separator between a Heading 2 or Heading 3 number and its title must be a normal space, not an extra tab
- The TOC must not have a black or gray document fill
- TOC rows must use the same regular, non-bold formatting
- TOC digits must be Persian digits:
  - `۰ ۱ ۲ ۳ ۴ ۵ ۶ ۷ ۸ ۹`

The dark screenshot seen previously was mainly Word Dark Mode and field shading. It was not a printable background fill.

## Headings and numbering

The heading hierarchy is:

- Heading 1: chapter title only, with no automatic list number
  - Example: `فصل اول: مقدمه`
  - Example: `ادبیات موضوع`
- Heading 2: section number
  - Example: `۱-۱ مقدمه و پیش‌زمینه`
- Heading 3: subsection number
  - Example: `۱-۲-۱ معماری ...`

Important rules:

- Heading 1, Heading 2, and Heading 3 are bold in the thesis body.
- TOC 1, TOC 2, and TOC 3 remain regular weight even when their source body headings are bold.
- Heading 1 paragraphs must not display an automatic number next to their title.
- Never apply Heading 1 to an empty paragraph: even an invisible empty Heading 1 advances the chapter counter and corrupts every following Heading 2/3 number.
- Keep any chapter designation, such as `فصل اول`, as literal title text rather than a generated list label.
- Heading 1 must remain in the underlying multilevel list with an empty displayed label. This keeps Heading 2 numbering reset by chapter: removing Heading 1 from the list causes Chapter 2 to continue incorrectly as `۸-۱` instead of `۱-۲`.
- The first section of Chapter 1 must be `۱-۱`.
- Chapter 2 sections must restart correctly as `۱-۲`, `۲-۲`, etc.
- Do not alter the outline levels:
  - Heading 1 → outline level 1
  - Heading 2 → outline level 2
  - Heading 3 → outline level 3
- Heading 2 and Heading 3 list levels should use a space after the number, not a tab.
- When changing numbering, verify both:
  1. Heading 1 remains text-only while Heading 2 and Heading 3 numbering remains correct in the body;
  2. the numbers generated in the TOC after using **Update entire table**.

## Persian numerals and Word fields

The TOC is a live Word `TOC` field. Its cached displayed text can be edited, but that edit is lost when the user selects **Update entire table**.

Therefore, a durable fix must also address:

- Word’s Arabic numeral display setting;
- the language metadata for Heading 2–3 numbering;
- the language metadata for TOC1–TOC3 styles;
- the TOC page-reference fields.

The Word numeral display setting used for this document is context-sensitive mode:

- `Application.Options.ArabicNumeral = 2`

This keeps digits in Persian headings and list labels Persian while leaving digits in Latin technical terms, formulas, bibliography text, years, volume numbers, RFC numbers, and identifiers such as `SHA3-256`, `X25519`, and `ML-KEM-768` in English.

After changing it, test by actually updating the complete TOC. Do not rely only on the cached XML text.

After Word refreshes the main TOC, `normalize_thesis_style.ps1` converts every cached section and page digit in that TOC to literal Persian Unicode digits and locks the TOC field. This keeps the main TOC fully Persian without changing English digits elsewhere. Rerun `apply_thesis_style.ps1` followed by `normalize_thesis_style.ps1` whenever the main TOC must be refreshed.

## Encoding rule

Never place Persian characters directly in a temporary PowerShell script unless the script encoding is explicitly controlled.

Windows PowerShell may read a UTF-8 script without a BOM as an ANSI file. This previously converted Persian digits into mojibake such as:

- `Û±`
- `Û²`
- `Û³`

For scripts that write Persian digits, use Unicode code points instead:

```powershell
[char](0x06F0 + $digit)
```

The Persian digit code points are `U+06F0` through `U+06F9`.

## Footnotes

Footnotes use two visual columns. Their required reading and numbering order is:

```text
left column    right column
1              3
2              4
```

In other words, Word must fill the left footnote column from top to bottom first, then continue at the top of the right column. It must not display the same notes as:

```text
left column    right column
3              1
4              2
```

This ordering is controlled by the section's column flow, not by manually moving individual footnotes. For every thesis section that can contain footnotes:

- `PageSetup.SectionDirection = 1`
- `PageSetup.TextColumns.FlowDirection = 0`
- The section must therefore have left-to-right column flow.
- Keep Persian body paragraphs right-to-left through their paragraph and heading styles.
- The `Footnote Text` style must use left-to-right reading order and regular left alignment.
- The `Footnote Reference` style and all footnote markers use English (`en-US`) number shaping.
- Existing footnote paragraphs must contain explicit LTR and left-alignment formatting.

These section and style settings make newly inserted footnotes follow the same left-column-first order automatically. If a new section is added, verify that it inherited the same section direction and column flow from the preceding body section.

## Safe editing workflow

Before changing `Thesis.docx`:

1. Confirm the exact active document is `Thesis.docx`.
2. Make a dated backup in the same folder.
3. Inspect the current TOC field, heading list strings, styles, and numbering definitions.
4. Make the smallest scoped change.
5. Save the document.
6. Reopen it in Word.
7. Use **Update entire table**.
8. Verify:
   - Heading 1 titles have no automatic number;
   - section numbering is correct;
   - all TOC digits are Persian;
   - no mojibake appears;
   - TOC rows are regular/non-bold;
   - dotted leaders and page alignment remain correct.

Keep the backup until the updated document has been visually checked.

## Verification checklist

Use this checklist for every future TOC or numbering change:

- [ ] `Thesis.docx` opens successfully in Word.
- [ ] `فهرست مطالب` is present and centered.
- [ ] `عنوان` and `صفحه` are present.
- [ ] TOC direction is RTL.
- [ ] TOC entries have one page-number tab and dotted leaders.
- [ ] No entry is split because of an extra number/title tab.
- [ ] Heading 1 chapter titles display as text-only (for example, `فصل اول: مقدمه`).
- [ ] Chapter 1 first section displays as `۱-۱`.
- [ ] Chapter 2 restarts correctly.
- [ ] All TOC digits display as Persian digits.
- [ ] No `Û`, `±`, `Ù`, or similar mojibake appears.
- [ ] No TOC row is unexpectedly bold.
- [ ] **Update entire table** does not undo the fixes.
- [ ] Body headings and page numbers remain intact.
- [ ] Footnotes fill the left column first, then the right column.
- [ ] Four footnotes appear visually as `(1 3)` and `(2 4)`, not `(3 1)` and `(4 2)`.
- [ ] A newly inserted footnote inherits left-to-right footnote formatting and the correct column order.
- [ ] Any newly created body section has `SectionDirection = 1` and `TextColumns.FlowDirection = 0`.

## Important distinction

There are three different kinds of numbers in this thesis:

1. Body heading/list numbers (Heading 2 and Heading 3; Heading 1 is text-only)
2. TOC heading and page-reference numbers
3. Numbers inside ordinary thesis text, figures, tables, equations, and references

Unless explicitly requested, a TOC correction should not rewrite every number in the entire thesis.

## Figure and table lists

- Every figure and table caption uses centered paragraph alignment, including captions inside text boxes.
- A floating caption text box must be anchored to its matching image and positioned directly below that image; do not leave the caption anchored to a nearby body paragraph or another figure.
- Figure and table captions use literal Persian chapter/sequence numbers so the hidden Heading 1 label cannot produce a `0` chapter prefix.
- Numbering restarts inside each chapter and is sequential among captions that actually exist.
- Captions inside text boxes must be included; Word's normal Table of Figures field omits them.
- `apply_thesis_style.ps1` rebuilds both front lists as separate `TOC 1` paragraphs with dotted leaders and Persian page numbers.
- Figure/table list hyperlinks remain black and un-underlined in both normal and followed (already clicked) states.
- The front-list page numbers are refreshed whenever `apply_thesis_style.ps1` is rerun.
- Keep the section-break paragraphs after the figure list and table list intact.

Current verified counts:

- 15 figures (verified 2026-10-08)
- 13 tables (verified 2026-10-08)

## Equation numbering

- Displayed formulas use English chapter-sequence labels in parentheses, such as `(2-1)`, `(2-2)`, and `(3-1)`.
- Restart the sequence in each chapter; chapter 1 currently has no displayed formulas.
- Inline notation and formulas used as table-cell symbols are not numbered.
- Current displayed-formula counts: chapter 2: 66; chapter 3: 20; chapter 4: 130; chapter 5: 92; chapter 6: 2; total: 310.
- Numbers use Word's native equation-array layout, with the equation centered and its number at the right.
- Each displayed formula line has its own paragraph. Trailing manual line breaks inside a numbered math array can cause Word to save invalid math XML; remove those breaks before applying native equation numbering.
- Seven long formulas use multiple lines; four of these also use 11.5-point math text to leave space for their labels. Body text formatting is preserved.
- Equation numbers are explicit labels. Adding or deleting displayed formulas requires renumbering the affected chapter and refreshing the three front lists afterward.

## Bibliography numbering

- The generated bibliography is finalized as static paragraphs after the `BIBLIOGRAPHY` field is refreshed.
- Each reference has a literal Persian list prefix from `U+06F0` through `U+06F9`.
- This avoids mixed digit shaping caused by English bibliography text and automatic Word list labels.
- The current bibliography is static after finalization. To add or change Word bibliography sources later, insert/update a new `BIBLIOGRAPHY` field first and then rerun `apply_thesis_style.ps1`.

## Recovery

If a future edit causes corruption:

- Close Word without saving the bad state.
- Restore the most recent dated backup.
- Do not use a broad recursive delete or reset command.
- Reapply the smallest required change.
- Run the full verification checklist above.
