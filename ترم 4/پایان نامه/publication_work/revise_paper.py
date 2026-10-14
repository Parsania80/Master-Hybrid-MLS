from pathlib import Path
p=Path(__file__).with_name('paper.md')
s=p.read_text(encoding='utf8')
s=s.replace('Reported thesis tables illustrate binary and quaternary probe sizes and a five-observation migration trace; their operation mismatch and unavailable raw artifacts limit inference. The prototype also uses a different combiner from the thesis specification.', 'A five-observation trace reported in the thesis illustrates nonmonotonic delivery costs and a final retirement-threshold crossing; the underlying raw observations are unavailable.')
s=s.replace('We present the thesis construction as the authoritative design, derive its communication tradeoffs, and reinterpret its numerical tables using supporting source-code evidence. The implementation supplies observations about a related experimental profile, rather than conformance evidence for the exact thesis combiner.', 'We present the thesis construction as the authoritative design, derive its communication tradeoffs, and examine a reported sequence of delivery costs. The numerical analysis supports the cost model; the reported trace illustrates the retirement rule without constituting independent validation of the complete construction.')
s=s.replace('their adequacy needs a construction-specific analysis. We do not silently import the prototype\'s different profile to fill these gaps.', 'their adequacy needs a construction-specific analysis. These unresolved choices limit the security conclusions that can be drawn from the design.')
s=s.replace('The prototype\'s observed trigger is narrower than a validated implementation of this forecast rule.', 'The forecast horizon and the safety margin require workload-specific justification before this rule can be treated as an operational recommendation.')
s=s.replace('The available native quaternary prototype does not implement this full join behavior and rejects post-transition Add/remapping. Its supported transition observations are therefore limited to Update and Remove.', 'This join behavior is a design requirement. A complete treatment must define how the authenticated mapping changes and how a new member obtains consistent state without receiving obsolete secrets. The reported trace considered below contains only Update and Remove events.')
s=s.replace('The implementation uses clamped rational statistics and blocks undefined cases; those are additional implementation choices. Its new-tree comparison is strictly greater than 0.70, whereas the thesis uses greater than or equal to 0.70. The final observation reported below satisfies both variants, so this discrepancy does not alter that particular decision.', 'A complete policy must define what happens for zero denominators and out-of-range values. We use the raw ratios only where they are defined and preserve the thesis\'s inequality in Equation (9). The numerical example below does not require clamping.')
s=s.replace('and the prototype\'s regression tests cannot supply one.', 'and the numerical results do not supply one.')
s=s.replace('The prototype retains classical Ed25519 authentication.', 'The hybrid encapsulation design does not itself specify a post-quantum replacement for classical signatures.')
s=s.replace('capable of forging those signatures.', 'capable of forging the retained classical signatures.')
s=s.replace('That example matches the prototype\'s wrapper lengths but is not a complete wire-size formula.', 'This is a conditional accounting example, not a measurement or a complete wire-size formula.')
start=s.index('# Prototype evidence and reported results')
end=s.index('# Discussion and limitations',start)
s=s[:start]+'''# Reported TreeCover delivery costs

## Source and interpretation

The following observations are transcribed from Table 5–7 of the thesis [4]. They describe five successive post-transition Remove and Update events. The original raw observations are unavailable, so the table is treated as a reported illustrative trace rather than an independently reproduced experiment. Its role is to make the cost-based retirement calculation concrete. It does not measure cryptographic security, execution time, network delay, or population-wide performance.

Table 4 preserves all endpoint counts and exact fractions. The new/old columns count usable nodes in the two structures. C_new and C_old are separate endpoint costs, while C_real is the reported cost of the selected mixed delivery. The architectural priority of new nodes, eligible old cover nodes, then leaves operates on subsets. It is not a rule that takes the minimum of the two total costs: in the first row C_real is 92 although C_old is 41. A cost-minimizing cover algorithm is therefore not established by these values.

@table Reported post transition delivery observations from thesis Table 5–7
Committer and event | New/old nodes | C_new | C_old | C_real | H_new | H_old
70 Remove | 6 / 29 | 111 | 41 | 92 | 15/116 | 85/116
10 Remove | 8 / 26 | 124 | 60 | 80 | 1/115 | 13/23
112 Update | 10 / 26 | 45 | 52 | 42 | 16/23 | 73/115
54 Update | 12 / 26 | 48 | 44 | 37 | 77/115 | 81/115
78 Remove | 13 / 25 | 44 | 47 | 41 | 40/57 | 77/114

## Threshold calculation and scope

The final H_new is 40/57, approximately 0.701754, and H_old is 77/114, approximately 0.675439. With theta_new = 0.70 and theta_old = 0.50, the new-tree branch of Equation (9) is true and the old-tree branch is false. Because the rule is disjunctive, the former is sufficient to authorize retirement. The table supports this arithmetic conclusion; it does not establish that retirement was accepted everywhere or that any particular compromise scenario has healed.

The preceding rows show why usable-node counts are not enough to assess the next delivery. Between the first and second observations the new usable-node count rises from six to eight, but C_new rises from 111 to 124 and H_new falls from 15/116 to 1/115. Between the third and fourth observations, H_new falls from 16/23 to 77/115 even as usable new nodes increase. Different committers and removals change the relevant recipient resolutions. A single monotonically increasing fraction of populated nodes cannot represent these effects.

The fractions are internally compatible with changing reference costs. For example, the first row is consistent with C_leaf = 126 and C_ideal = 10, giving (126 − 111)/(126 − 10) = 15/116. The last row is consistent with C_leaf = 124 and C_ideal = 10, giving (124 − 44)/(124 − 10) = 40/57 and (124 − 47)/(124 − 10) = 77/114. These references are algebraic reconstructions from the table, not additional observed fields. They show that the displayed ratios can be checked without interpreting endpoint counts as bytes or timings.

The trace is too short and too narrowly specified to estimate expected retirement time. It provides no independent repetitions, distribution of workloads, or confidence interval. A different committer sequence could reach the cost threshold earlier or later, and repeated removals could reverse an apparent improvement. No general claim that five updates suffice follows from these observations.

'''+s[end:]
s=s.replace('then either implement it faithfully or give the implementation profile a separate specification and analysis.', 'and establish a conformance specification for subsequent validation.')
s=s.replace('The thesis and archived notes preserve reported values, while source code explains their column semantics and operation substitutions. Without the original run artifacts and a pinned matching execution state, the tables cannot be independently replayed as a validated experiment. Preserving their values with these limitations is preferable to inferring missing measurements or treating an unrelated earlier experiment manifest as their provenance.', 'The thesis preserves reported values but not the complete raw observations and execution controls needed to replay the trace. Its numerical table therefore serves as an illustration of the proposed metric, while the analytical tables are directly reproducible from their stated formulas. A future evaluation should preserve original outputs, exact topology and membership histories, recipient sets, and all parameters used to compute the reference costs.')
s=s.replace('The reported prototype tables illustrate delivery and retirement behavior within a narrower implementation profile. They do not prove the exact thesis construction secure or establish general performance superiority.', 'The reported thesis trace illustrates nonmonotonic delivery costs and a retirement-threshold crossing. It does not prove the construction secure or establish general performance superiority.')
s=s.replace('Its reported observations originate in the thesis tables and supporting implementation records. The original CSV/JSON run artifacts are unavailable. No public archival identifier for the implementation or dataset is asserted here.', 'Its reported observations originate in the thesis tables. The underlying raw observations are unavailable, and no public dataset identifier is asserted here. All analytical values in this article follow from the equations and parameters stated in the text.')
# RFC 9180 is retained only for the precise distinction between HPKE and the thesis hybrid combiner.
needle='The hybrid output is an encryption input for path-secret transport; it is not itself the group epoch secret.'
s=s.replace(needle,needle+' The term hybrid in Hybrid Public Key Encryption denotes a KEM–KDF–AEAD composition [11]; it does not by itself mean a classical/post-quantum combiner.')
p.write_text(s,encoding='utf8')
print('Revised manuscript words:',len(s.split()))
