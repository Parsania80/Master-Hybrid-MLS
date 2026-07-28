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
- The separator between a heading number and its title must be a normal space, not an extra tab
- The TOC must not have a black or gray document fill
- TOC rows must use the same regular, non-bold formatting
- TOC digits must be Persian digits:
  - `۰ ۱ ۲ ۳ ۴ ۵ ۶ ۷ ۸ ۹`

The dark screenshot seen previously was mainly Word Dark Mode and field shading. It was not a printable background fill.

## Heading numbering

The heading hierarchy is:

- Heading 1: chapter number
  - Example: `۱ فصل اول: مقدمه`
- Heading 2: section number
  - Example: `۱-۱ مقدمه و پیش‌زمینه`
- Heading 3: subsection number
  - Example: `۱-۲-۱ معماری ...`

Important rules:

- Chapter 1 must always begin at `۱`, never `۲`.
- The first section of Chapter 1 must be `۱-۱`.
- Chapter 2 sections must restart correctly as `۱-۲`, `۲-۲`, etc.
- Do not alter the outline levels:
  - Heading 1 → outline level 1
  - Heading 2 → outline level 2
  - Heading 3 → outline level 3
- Heading list levels should use a space after the number, not a tab.
- When changing numbering, verify both:
  1. the heading numbers in the body;
  2. the numbers generated in the TOC after using **Update entire table**.

## Persian numerals and Word fields

The TOC is a live Word `TOC` field. Its cached displayed text can be edited, but that edit is lost when the user selects **Update entire table**.

Therefore, a durable fix must also address:

- Word’s Arabic numeral display setting;
- the language metadata for Heading 1–3 numbering;
- the language metadata for TOC1–TOC3 styles;
- the TOC page-reference fields.

The Word numeral display setting used for this document is the Hindi/Persian-compatible mode:

- `Application.Options.ArabicNumeral = 1`

After changing it, test by actually updating the complete TOC. Do not rely only on the cached XML text.

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
   - Chapter 1 is `۱`, not `۲`;
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
- [ ] Chapter 1 displays as `۱`.
- [ ] Chapter 1 first section displays as `۱-۱`.
- [ ] Chapter 2 restarts correctly.
- [ ] All TOC digits display as Persian digits.
- [ ] No `Û`, `±`, `Ù`, or similar mojibake appears.
- [ ] No TOC row is unexpectedly bold.
- [ ] **Update entire table** does not undo the fixes.
- [ ] Body headings and page numbers remain intact.

## Important distinction

There are three different kinds of numbers in this thesis:

1. Body heading/list numbers
2. TOC heading and page-reference numbers
3. Numbers inside ordinary thesis text, figures, tables, equations, and references

Unless explicitly requested, a TOC correction should not rewrite every number in the entire thesis.

## Recovery

If a future edit causes corruption:

- Close Word without saving the bad state.
- Restore the most recent dated backup.
- Do not use a broad recursive delete or reset command.
- Reapply the smallest required change.
- Run the full verification checklist above.
