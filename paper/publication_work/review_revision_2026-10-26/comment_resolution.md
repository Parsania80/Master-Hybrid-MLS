# Professor review revision 26 October 2026

All 31 comments in reviews/ParsaniaPaper-Ver1.pdf are addressed below. The clean Word manuscript is the canonical source; the highlighted PDF compares the revision with the professor-reviewed PDF. Yellow marks added or replaced text; annotation notes explain deletions. The original annotated review remains unchanged.

## Comment 1 on page 1

حذف

Applied: Removed the honorific Dr from the author line in the clean manuscript and synchronized source.

## Comment 2 on page 1

حذف

Applied: Replaced the coined title with Adaptive Arity and Gradual Tree Migration in Hybrid TreeKEM.

## Comment 3 on page 1

ابتدا یک جمله بیاورید که منظور از طرحهای هایبرید و مزایای آنها را بیان کند و سپس این جمله را بیاورید.

Applied: Abstract opens by defining classical/post-quantum hybridization and its motivation.

## Comment 4 on page 1

قبل از این یک جمله بیاورید و TreeKEM را معرقی کنید.

Applied: Abstract introduces TreeKEM and its role in MLS before describing the mechanism.

## Comment 5 on page 1

خواننده نمیداند که چیست. بیان را تغییر دهید.

Applied: Replaced commit secret in the abstract with a plain description; introduction explains the fresh contribution to the group secret.

## Comment 6 on page 1

خواننده نمیداند که چیست.

Applied: Replaced path secrets in the abstract with secret values needed to establish new keys; introduction defines path secret.

## Comment 7 on page 1

يعنی چه؟ قبلا توضیحی داده نشده!

Applied: Replaced healthy-tree approximation with a balanced tree whose required internal keys are available.

## Comment 8 on page 1

؟؟؟؟؟

Applied: Replaced modeled payload with public-key and encapsulation data per update and stated exclusions.

## Comment 9 on page 1

؟؟؟؟

Applied: Replaced unexplained modeled cost wording with an explicitly conditional transition example.

## Comment 10 on page 1

evaluation

Applied: Abstract now uses security evaluation and describes communication analysis directly.

## Comment 11 on page 1

جنس این کامیت چیست؟ از جنس يک پیام است؟ چه کسی تولید و ارسال میکند؟ خود MLS چگونه از آن یاد میکند؟

Applied: Introduction identifies a Commit as an MLS message created and broadcast by a member acting as committer, initiating an epoch; cites RFC 9420 Sections 7.5 and 12.4.

## Comment 12 on page 1

کدام کلیدهای عمومی؟؟؟؟ در جملات قبل حرفی از کلید عمومی نبود که الان در این جمله به آنها ارجاع میدهید!

Applied: Introduction explains the public encryption keys at tree nodes before discussing transmission cost.

## Comment 13 on page 1

به نظرم مقدمه نباید مستقیما با MLS شروع شود. بلکه باید با اهمیت تبادل کلید گروهی شروع شود بعد هم با مفاهیم امنیت پساکوانتومی و هیبریدی ادامه یابد و بعد به MLS پرداخته شود.

Applied: Introduction starts with group key exchange, then quantum and hybrid security, then MLS.

## Comment 14 on page 1

يعنی چی makes the cost relevant؟؟؟

Applied: Replaced makes the cost relevant with an explicit explanation that two key/ciphertext components increase update communication.

## Comment 15 on page 1

in a 

Applied: Rewrote the prior-work sentence with Alwen et al. as subject, removing the ungrammatical phrase.

## Comment 16 on page 1

حذف 

Applied: Deleted the first-author thesis phrase and its citation from the introduction; retained source provenance in its own section.

## Comment 17 on page 1

یه جوری نوشتین که انگار یک اصطلاح کاملا یونیورسال است. این اصطلاح خودنان است؟ اگر بله اصلا جالب نیست. از نام معمولی استفاده کنید.

Applied: Removed TreeCover from manuscript, metadata, headings, and keywords; uses ordinary descriptions of retaining the old tree.

## Comment 18 on page 1

يعنی چه گره هایی؟؟؟؟ نامفهوم و غیر دقیق است.

Applied: Introduction states key authentication, private-key availability, and exclusion of removed members for a retained node.

## Comment 19 on page 1

اینجا هنوز مسئله برای خواننده روشن نیست. باید توضیح دهید که اگر درخت همچنان باینری بماند چه عیبی حادث میشود.

Applied: Explains why a binary tree can transmit more public keys and common ciphertext components than a shallower tree.

## Comment 20 on page 1

اول بگویید که KEM چیست و بعد بروید سراغ mKEM.

Applied: Defines KEM before introducing multi-recipient KEM.

## Comment 21 on page 1

برای خواننده بگویید که چرا و با چه هدفی این طرحها به سراغ تغییر درخت رفته اند.

Applied: Explains the depth-versus-recipient tradeoff that motivates changing the tree degree.

## Comment 22 on page 1

کاور دیگه چيه؟ اگر منظورتون درخت قدیمیه خب نویسین old tree.

Applied: Uses old tree in the introduction; reserves the mathematical set-cover term for its formal definition in Section 4.2.

## Comment 23 on page 1

قشنگ مسئله رو باز کنید و ساده بنویسید که معیار مورد نظر برای بازنشسته کردن (کنار گذاشتن) درخت قدیمی چیه؟

Applied: Our Contribution explains both threshold alternatives for discarding the old tree and the normalization baseline.

## Comment 24 on page 1

بیان من در آوردی است (old-tree را به عنوان صفت بکار برده اید). بعد delivery به چه چیزی برمیگردد؟ چه چیزی باید deliver شود؟ ساده و دقیق بنویسید نه تلگرافی و مبهم. introduction باید مسئله را روشن و دقیق بیان کند. بعد هم نوآوریها و نتایج حاصل را بدون ذکر جزئیات بیان کند.

Applied: Describes who encrypts and distributes which new path secrets using keys from the old tree in complete sentences.

## Comment 25 on page 1

نباید بگویید نوآوری شما چه چیزهایی نیست. بلکه بگویید چه چیزی هست.

Applied: States positive contributions and deletes the list of what is not claimed as novel.

## Comment 26 on page 1

تز؟؟؟؟دقیق بگویید چیزی که در این مقاله ارایه میشود چیست؟ یک طرح است یا یک چارچوب یا یک مکانیزم یا یک الگوریتم یا یک سیاست؟ چیست؟

Applied: Identifies the contribution consistently as a migration mechanism and removes authoritative thesis framing.

## Comment 27 on page 1

این بیان غیر مرسوم است

Applied: Replaces the scope sentence with concrete design, evaluation, and security contributions.

## Comment 28 on page 1

اصطلاح غیر مرسوم. بیان را ساده و دقیق کنید.

Applied: Replaces the healthy-tree byte formula label with plain descriptions of the counted components and reference tree.

## Comment 29 on page 1

این پاراگراف را تخت یک زیربخش با عنوان Our Contribution  بازنویسی کنید

Applied: Adds an automatically numbered Our Contribution subsection with the mechanism and findings.

## Comment 30 on page 2

يک زیربخش با عنوان Paper Organisation بیاورید و در آن بگویید بخشهای بعدی شامل چه هستند.

Applied: Adds an automatically numbered Paper Organisation subsection describing Sections 2 through 8.

## Comment 31 on page 2

This work

Applied: Changes the Table 1 row label from Present study to This work.

